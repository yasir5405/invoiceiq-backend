import express from "express";
import {
  hashPassword,
  matchPasswordAndConfirmPassword,
  verifyJWT,
} from "../middlewares/auth.middleware.js";
import {
  forgetPassword,
  getUserInfo,
  loginUser,
  logout,
  registerUser,
  resetPassword,
  tokenRefresh,
  verifyEmail,
} from "../controllers/auth.controller.js";

const Router = express.Router;

const userRouter = Router();

// @route to create a new user in the database, uses middlewares for matching both passwords and confirmPassword, hashing the password and then calling the register user controller
userRouter.post(
  "/register",
  matchPasswordAndConfirmPassword,
  hashPassword,
  registerUser
);

// @route to verify user's email after account creation
userRouter.get("/verify-email", verifyEmail);

// @route to verify user credentials and issue them tokens(access and refresh tokens)
userRouter.post("/login", loginUser);

// @route to fetch user details once they have logged in, it uses the verifyJWT middlware to verify the authenticity of the request
userRouter.get("/my-details", verifyJWT, getUserInfo);

// @route to issue a new access token after expiration with the refresh token sent by the client in the cookie
userRouter.post("/refresh-token", tokenRefresh);

// @route to revoke the refresh token of the user stores in database and clear the cookie sent to the client
userRouter.post("/logout", logout);

userRouter.post("/forgot-password", forgetPassword);

userRouter.patch("/reset-password", resetPassword);

export { userRouter };
