import express from "express";
import { googleLogin } from "../controllers/auth.controller.js";

const Router = express.Router;

const authRouter = Router();

authRouter.get("/test", (req, res) => {
  res.send("Hello from auth server");
});

authRouter.get("/google", googleLogin);

export { authRouter };
