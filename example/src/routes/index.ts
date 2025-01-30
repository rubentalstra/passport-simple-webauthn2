// src/routes/index.ts
import express from "express";
import authRoutes from "./auth";

const router = express.Router();

router.use("/auth", authRoutes);

router.get("/", (req, res) => {
    res.send("Welcome to the SimpleWebAuthn Example!");
});

export default router;