import userModel from "../models/user.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { generateTokens } from "../middleware/authJWT.js"
import { body, validationResult } from "express-validator";
import tokenModel from "../models/token.model.js";


//buat array validation register
export const validateResgisterInput = [
    body("username").notEmpty().withMessage("Username harus diisi"),
    body("password")
        .notEmpty().withMessage("Password harus diisi")
        .isLength({ min: 8 }).withMessage("Password minimal 8 karakter"),
    body("firstname").notEmpty().withMessage("Nama depan harus diisi"),
    body("lastname").notEmpty().withMessage("Nama belakang harus diisi"),
];

//buat array validation login
export const validateLoginInput = [
    body("username").notEmpty().withMessage("Username harus diisi"),
    body("password").notEmpty().withMessage("Password harus diisi"),
];


//buat user baru
export const register = async (req, res, next) => {
    try {
        const { username, password, firstname, lastname } = req.body;

        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const err = new Error("Harap masukkan data yang valid.");
            err.statusCode = 400;
            err.errors = errors.array();
            throw err
        }

        const salt = 10;
        const hashPassword = await bcrypt.hash(password, salt);
        const user = new userModel({
            username,
            password: hashPassword,
            firstname,
            lastname
        });
        await user.save();
        const tokens = await generateTokens(user._id);
        res.cookie("access_token", tokens.accessToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true,
        });
        res.cookie("refresh_token", tokens.refreshToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true,
        });
        res.status(201).json({ message: "User berhasil dibuat." });
    } catch (err) {
        next(err);
    }
};

//login user
export const loginUser = async (req, res, next) => {
    try {
        const { username, password } = req.body;

        //input validasi
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            const err = new Error("Harap masukkan data yang valid.");
            err.statusCode = 400;
            err.errors = errors.array();
            throw err;
        }
        const user = await userModel.findOne({ username });
        if (!user) {
            const err = new Error("User tidak ditemukan.");
            err.statusCode = 401;
            throw err;
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            const err = new Error("Password tidak valid.");
            err.statusCode = 401;
            throw err;
        }

        const tokens = await generateTokens(user._id);
        res.cookie("access_token", tokens.accessToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true
        });
        res.cookie("refresh_token", tokens.refreshToken, {
            httpOnly: true,
            sameSite: "none",
            secure: true
        });
        res.status(200).json({ message: "Login berhasil." });
    } catch (err) {
        next(err);
    }
};

// export const logout = async (req, res, next) => {
//     try {
//         const refreshToken = req.cookies.refresh_token;
//         const decoded = jwt.decode(refreshToken);
//         if(!decoded || !decoded.userId) {
//             throw new Error("Invalid token");
//         }
//         const userId = decoded.userId;
//         await tokenModel.deleteOne({ userId: userId });
//         res.clearCookie("access_token");
//         res.clearCookie("refresh_token");
//         res.status(200).json({ message: "Logout berhasil" });
//     } catch (err) {
//         next (err);
//     }
// };
export const logout = async (req, res, next) => {
    try {
        res.clearCookie("access_token", { httpOnly: true, sameSite: "none", secure: true });
        res.clearCookie("refresh_token", { httpOnly: true, sameSite: "none", secure: true });
        res.status(200).json({ message: "Berhasil logout" });
    } catch (err) {
        next(err);
    }
}