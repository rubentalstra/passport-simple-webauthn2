import express, { Request, Response } from "express";
import { User } from "../models/User";

const router = express.Router();

router.get("/passkeys", async (req: Request, res: Response) => {
    if (!req.session.userID) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        const user = await User.findOne({ userID: req.session.userID }).lean();
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ passkeys: user.passkeys });
    } catch (err) {
        console.error("Error fetching passkeys:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

export default router;