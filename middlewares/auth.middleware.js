import bcrypt from "bcrypt";
import jsonwebtoken from "jsonwebtoken";
import { UserModel } from "../models/users.model.js";

const hashPassword = async (req, res, next) => {
  const password = req.body.password;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    req.body.password = hashedPassword;

    next();
  } catch (error) {
    console.log(error, " Error in hashing pasword.");
    return res.status(500).json({ message: "Error in hashing password." });
  }
};

const matchPasswordAndConfirmPassword = (req, res, next) => {
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  if (!confirmPassword || confirmPassword.length === 0) {
    return res.status(400).json({ message: "Please enter confirm password" });
  }

  if (confirmPassword !== password) {
    return res
      .status(400)
      .json({ message: "Password and confirm password do not match." });
  }

  next();
};

const verifyJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "No token or bad format. Unauthorized.",
    });
  }

  const accessToken = authHeader.split(" ")[1];

  if (!accessToken) {
    return res
      .status(401)
      .json({ success: false, message: "Missing token. Unauthorized." });
  }

  try {
    const decoded = jsonwebtoken.verify(accessToken, process.env.JWT_SECRET);
    const userId = decoded.id;

    const user = await UserModel.findById(userId);

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid token." });
    }

    const { password: _, ...safeUser } = user._doc;

    req.user = safeUser;
    next();
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      // console.log("Token has expired");
      return res.status(401).json({ success: false, message: "Token expired" });
    } else {
      // console.log("Token invalid for other reasons");
      return res.status(401).json({ success: false, message: "Invalid token" });
    }
  }
};

export { hashPassword, matchPasswordAndConfirmPassword, verifyJWT };
