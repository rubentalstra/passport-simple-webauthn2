import express from "express";
import authRoutes from "./auth";

const router = express.Router();

router.use("/auth", authRoutes);

router.get("/", (req, res) => {
    res.send("✅ SimpleWebAuthn Example Server Running!");
});

export default router;