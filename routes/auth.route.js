import express from "express";
import {
  loginUser,
  logoutUser,
  registerUser,
  verifyUser,
} from "../controllers/auth.controller.js";

const userRouter = express.Router();

userRouter.post("/register", registerUser);

userRouter.post("/login", loginUser);

userRouter.post("/verify", verifyUser);

userRouter.post("/logout", logoutUser);

export default userRouter;
