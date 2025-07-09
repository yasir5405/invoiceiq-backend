import { UserModel } from "../models/users.model.js";
import { verificationTokenModel } from "../models/verification-token.model.js";
import {
  resetPasswordLink,
  sendVerificationEmail,
} from "../utils/sendEmail.js";
import {
  validateLoginBody,
  validateRegisterBody,
  validateUpdateUserBody,
} from "../utils/validationSchema.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
import jsonwebtoken from "jsonwebtoken";
import { refreshTokenModel } from "../models/refresh-token.model.js";
import { z } from "zod";
import { resetPasswordTokenModel } from "../models/reset-password-token.model.js";
import { oauth2Client } from "../utils/googleConfig.js";

// Controller to create a user in the database
const registerUser = async (req, res) => {
  const parsedBody = validateRegisterBody(req.body);

  if (!parsedBody.success) {
    return res.status(400).json({
      success: false,
      message: "Incorrect data format",
      errors: parsedBody.error.errors[0].message,
    });
  }

  const { name, email, password } = parsedBody.data;

  try {
    const user = await UserModel.create({
      name: name,
      email: email,
      password: password,
      profileImage: null,
      isVerified: false,
    });

    const { password: _, ...safeUser } = user._doc;

    res.status(201).json({
      success: true,
      message: "Account successfully created.",
      user: safeUser,
    });

    const token = crypto.randomBytes(32).toString("hex");
    const expiredAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await verificationTokenModel.create({
      token: token,
      userId: user._id,
      expiresAt: expiredAt,
    });
    await sendVerificationEmail(user.email, token);
  } catch (error) {
    console.log(error, " Error creating an account");
    return res
      .status(500)
      .json({ success: false, message: "Internal server error." });
  }
};

// Function to verify the user's email after they create an account
const verifyEmail = async (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "No token found. Unauthorised." });
  }

  try {
    const storedToken = await verificationTokenModel.findOne({ token: token });

    if (!storedToken || storedToken.expiresAt < new Date()) {
      return res
        .status(400)
        .json({ success: false, message: "Token invalid or expired." });
    }

    const user = await UserModel.findById(storedToken.userId);

    if (!user) {
      return res.status(404).json({ success: false, message: "Unauthorised." });
    }

    if (user.isVerified) {
      return res
        .status(400)
        .json({ success: false, message: "Email is already verified." });
    }

    user.isVerified = true;
    await user.save();
    await verificationTokenModel.findByIdAndDelete(storedToken._id);

    return res
      .status(200)
      .json({ success: true, message: "Email verified successfully!" });
  } catch (error) {
    return res
      .status(500)
      .json({ success: false, message: "Internal server error." });
  }
};

// Function to verify the user's info and then give them JWT tokens (accessToken and refreshToken cookie)
const loginUser = async (req, res) => {
  const parsedBody = validateLoginBody(req.body);

  if (!parsedBody.success) {
    return res.status(401).json({
      success: false,
      message: "Invalid data format.",
      errors: parsedBody.error.errors[0].message,
    });
  }

  const { email, password } = parsedBody.data;

  try {
    const user = await UserModel.findOne({ email: email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    if (!user.isVerified) {
      return res.status(401).json({
        success: false,
        message: "Please verify your email before continuing.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res
        .status(400)
        .json({ success: false, message: "Wrong credentials." });
    }

    const accessToken = jsonwebtoken.sign(
      {
        email: user.email,
        id: user._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jsonwebtoken.sign(
      {
        email: user.email,
        id: user._id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    await refreshTokenModel.create({
      token: refreshToken,
      userId: user._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const { password: _, ...safeUser } = user._doc;

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    // console.log("login sucessful", safeUser);

    return res.status(200).json({
      success: true,
      message: "Login successful.",
      accessToken: accessToken,
      user: safeUser,
    });
  } catch (error) {
    console.error("Internal server error: ", error.message);
    return res.status(500).json({ success: false, error: error.message });
  }
};

// Function for issuing a new accessToken after verifying the refreshToken recieved in cookie
const tokenRefresh = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (!refreshToken) {
    return res
      .status(401)
      .json({ success: false, message: "Refresh token not found." });
  }

  try {
    const decoded = jsonwebtoken.verify(refreshToken, process.env.JWT_SECRET);

    if (!decoded.id) {
      console.log("Decoded refresh token missing user id:", decoded);
      return res
        .status(401)
        .json({ success: false, message: "Invalid refresh token payload" });
    }

    const storedToken = await refreshTokenModel.findOne({
      token: refreshToken,
      userId: decoded.id,
      isRevoked: false,
      expiresAt: { $gt: new Date() },
    });

    if (!storedToken) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid refresh token." });
    }

    const newAccessToken = jsonwebtoken.sign(
      {
        email: decoded.email,
        id: decoded.id,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1m" }
    );

    // console.log("New Access Token Payload:", {
    //   id: decoded.id,
    //   email: decoded.email,
    // });

    // console.log("New Access Token:", newAccessToken);

    return res.json({ success: true, accessToken: newAccessToken });
  } catch (error) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid refresh token" });
  }
};

// Function to logout the user and revoke their refreshToken in the database
const logout = async (req, res) => {
  const { refreshToken } = req.cookies;

  if (refreshToken) {
    await refreshTokenModel.updateOne(
      {
        token: refreshToken,
      },

      { isRevoked: true }
    );
  }

  res.clearCookie("refreshToken", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
  });

  return res.json({ success: true, message: "Logged out successfully." });
};

// Function to query the database and fetch user details
const getUserInfo = async (req, res) => {
  const user = req.user;
  if (!user) {
    return res.status(401).json({ success: false, message: "Unauthorised." });
  }

  res
    .status(200)
    .json({ success: true, message: "User data fetched!", user: user });
};

// Function to receive email for forget-password
const forgetPassword = async (req, res) => {
  const requiredBody = z.object({
    email: z
      .string({
        description:
          "Enter email to recieve link to your mail to reset your password.",
        required_error: "Email is required.",
      })
      .email(),
  });

  const parsedBody = requiredBody.safeParse(req.body);

  if (!parsedBody.success) {
    return res.status(401).json({
      success: false,
      message: "Invalid email format.",
      errors: parsedBody.error.errors[0].message,
    });
  }

  const { email } = parsedBody.data;

  try {
    const user = await UserModel.findOne({ email: email });

    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "No user found." });
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiredAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await resetPasswordTokenModel.create({
      token: token,
      userId: user._id,
      expiresAt: expiredAt,
    });

    await resetPasswordLink(email, token);

    res.status(200).json({
      success: true,
      message: "Password reset link sent to your registered email.",
    });
  } catch (error) {
    return res.status(500).json({ status: false, error: error.message });
  }
};

// Function to reset the password for user's account
const resetPassword = async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(401).json({ success: false, message: "Missing token." });
  }

  try {
    const storedToken = await resetPasswordTokenModel.findOne({ token: token });

    if (!storedToken || storedToken.expiresAt < new Date()) {
      return res
        .status(404)
        .json({ success: false, message: "Invalid token." });
    }

    const requiredBody = z.object({
      password: z
        .string({
          description: "Choose a password.",
          required_error: "Please enter your password before continuing.",
        })
        .min(8, { message: "Password should be at least 8 characters long." })
        .max(100, {
          message: "Password should not be more than 100 characters long.",
        }),
      confirmPassword: z
        .string({
          description: "Confirm your password.",
          required_error: "Please confirm your password before continuing.",
        })
        .min(8, { message: "Password should be at least 8 characters long." })
        .max(100, {
          message: "Password should not be more than 100 characters long.",
        }),
    });

    const parsedBody = requiredBody.safeParse(req.body);

    if (!parsedBody.success) {
      return res.status(401).json({
        success: false,
        message: "Invalid data format",
        error: parsedBody.error.errors[0].message,
      });
    }

    const { password, confirmPassword } = parsedBody.data;

    if (password !== confirmPassword) {
      return res.status(401).json({
        success: false,
        message: "Password and confirm password don't match.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await UserModel.findById(storedToken.userId);

    if (!user) {
      return res.status(404).json({ success: false, message: "No user found" });
    }

    user.password = hashedPassword;
    await user.save();
    await resetPasswordTokenModel.findByIdAndDelete(storedToken._id);

    res
      .status(200)
      .json({ success: true, message: "Password changed successfully." });
  } catch (error) {
    return res.status(500).json({ status: false, error: error.message });
  }
};

// Function to handle google login/user account creation
const googleLogin = async (req, res) => {
  try {
    const { code } = req.query;
    const googleRes = await oauth2Client.getToken(code);
    oauth2Client.setCredentials(googleRes.tokens);

    const userRes = await fetch(
      `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${googleRes.tokens.access_token}`,
      {
        method: "GET",
      }
    );

    const userInfo = await userRes.json();

    const { email, name, picture, id: googleId } = userInfo;

    let user = await UserModel.findOne({ email: email });

    if (!user) {
      user = await UserModel.create({
        name: name,
        email: email,
        profileImage: picture,
        googleId: googleId,
        isVerified: true,
      });
    } else {
      user.profileImage = picture;
      if (!user.googleId) {
        user.googleId = googleId;
        user.isVerified = true;
      }
      await user.save();
    }

    const accessToken = jsonwebtoken.sign(
      {
        email: user.email,
        id: user._id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "15m",
      }
    );

    const refreshToken = jsonwebtoken.sign(
      {
        email: user.email,
        id: user._id,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "7d",
      }
    );

    await refreshTokenModel.create({
      token: refreshToken,
      userId: user._id,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });

    const { password: _, ...safeUser } = user._doc;

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    });

    return res.status(200).json({
      success: true,
      message: "Login successful.",
      accessToken: accessToken,
      user: safeUser,
    });
  } catch (error) {
    console.error("Internal server error: ", error);
    return res.status(500).json({ success: false, error: error.message });
  }
};

const updateUserInfo = async (req, res) => {
  const parsedBody = validateUpdateUserBody(req.body);

  if (!parsedBody.success) {
    console.log("Invalid data format.");
    return res.status(400).json({
      success: false,
      message: "Invalid data format.",
      errors: parsedBody.error.errors[0].message,
    });
  }

  const { name, email } = parsedBody.data;

  const user = req.user;

  const updatedName = name ?? user.name;
  const updatedEmail = email ?? user.email;

  try {
    const updatedUser = await UserModel.findByIdAndUpdate(
      user._id,
      {
        name: updatedName,
        email: updatedEmail,
      },
      { new: true }
    );
    // console.log(updatedUser);

    const { password: _, ...safeUser } = updatedUser._doc;

    res.status(200).json({
      success: true,
      message: "User info updated successfully.",
      user: safeUser,
    });
  } catch (error) {
    console.error("Internal server error.");
    res.status(500).json({
      success: false,
      message: "Internal server error",
      error: error.message,
    });
  }
};

export {
  registerUser,
  verifyEmail,
  loginUser,
  tokenRefresh,
  logout,
  getUserInfo,
  forgetPassword,
  resetPassword,
  googleLogin,
  updateUserInfo,
};
