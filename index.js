import express from "express";
import dotenv from "dotenv";
dotenv.config();
import cookieParser from "cookie-parser";
import { userRouter } from "./routes/user.route.js";
import { authRouter } from "./routes/googleAuth.route.js";
import { connectDB } from "./config/db.js";
import cors from "cors";

const app = express();

// Middleware for json parsing sent in req.body
app.use(express.json());

// Middleware for parsing cookies recieved
app.use(cookieParser());

// Middleware for cors for cross origin requests
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://invoiceiq-sigma.vercel.app",
      "https://www.invoiceiq.xyz",
    ],
    credentials: true,
  })
);

// Database connection function
connectDB();

const PORT = process.env.PORT;

app.get("/", (req, res) => {
  res.json({
    message: "Welcome to invoiceIQ's backend",
  });
});

// Auth route(users)
app.use("/api/auth", userRouter);
app.use("/auth", authRouter);

app.listen(PORT || 3000, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
