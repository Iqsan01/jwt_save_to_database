import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import tokenModel from "../models/token.model.js";

const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;

//funsi untuk menghasilkan access token
export const generateAccessToken = (userId) => {
    try {
        const accessToken = jwt.sign({ userId }, accessTokenSecret, {
            expiresIn: "1h",
        });
        return accessToken;
    } catch (err) {
        throw new Error("Gagal menghasilkan access token.");
    }
};

//verifikasi access token
export const verifyAccessToken = async (accessToken) => {
    try {
        const decoded = jwt.verify(accessToken, accessTokenSecret);
        const token = await tokenModel.findOne({ userId: decoded.userId, accessToken: accessToken });
        if (!token) {
            throw new Error("Token tidak ditemukan.");
        }
        return decoded;
    } catch (err) {
        console.log(err);
        throw new Error("Invalid token");
    }
};

//verifikasi refresh token
export const verifyRefreshToken = async (refreshToken) => {
    try {
        const decoded = jwt.verify(refreshToken, refreshTokenSecret);
        const token = await tokenModel.findOne({ userId: decoded.userId, refreshToken: refreshToken });
        if(!token) {
            throw new Error("Token tidak ditemukan.");
        }
        return decoded;
    } catch (err) {
        console.log(err);
        throw new Error("Invalid refresh token ");
    }
};

//fungsi untuk menghasilkan refresh token
export const generateRefreshToken = async () => {
    const refreshToken = await bcrypt.hash(Math.random().toString(), 10);
    return refreshToken;
};

//fungsi untuk memperbarui access token dan refresh token
export const refreshTokens = async (refreshToken) => {
    try {
        const payload = jwt.verify(refreshToken, refreshTokenSecret);
        const userId = payload.userId;

        //cari token didatabase
        const token = await tokenModel({ userId: userId });
        //periksa apakah token telah ditemukan
        if (!token) {
            throw new Error("Token tidak ditemukan");
        }

        //periksa apakah refreshtoken dari database dan client sesuai
        if (token.refreshToken !== refreshToken) {
            throw new Error("Token tidak valid.");
        }

        const accessToken = generateAccessToken(userId);
        const newRefreshToken = await generateRefreshToken();

        //update refersh token pada database
        token.refreshToken = newRefreshToken;
        await token.save();

        return {
            accessToken,
            refreshToken: newRefreshToken,
        };
    } catch (err) {
        throw err;
    }
};

//fungsi untuk menghasilkan access token dan refresh token
export const generateTokens = async (userId) => {
    try {
        const accessToken = generateAccessToken(userId);
        const refreshToken = await generateRefreshToken();

        //simpan accessToken dan refreshToken ke database
        const tokenPair = new tokenModel({
            userId: userId,
            accessToken: accessToken,
            refreshToken: refreshToken,
            accessExpiresAt: new Date(Date.now() + 3600000), //accessToken berlaku 1 jam
            refreshExpiresAt: new Date(Date.now() + 604800000), //refreshToken berlaku 7 hari
        });

        await tokenPair.save();

        return {
            accessToken,
            refreshToken
        };
    } catch (err) {
        throw err;
    }
};
