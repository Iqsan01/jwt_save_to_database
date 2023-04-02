import { Router } from "express";
import { loginUser, logout, register, validateLoginInput, validateResgisterInput } from "../controllers/auth.controller.js";

const router = Router();

router.post("/register",validateResgisterInput, register)
router.post("/login",validateLoginInput, loginUser)
router.post("/logout",logout)
export default router;