import express, { NextFunction, Request, Response } from "express";
import passport from "passport";
import { MongoUserStore } from "../stores/MongoUserStore";
import { MongoChallengeStore } from "../stores/MongoChallengeStore";
import {WebAuthnStrategy} from "passport-simple-webauthn2";

const router = express.Router();
const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

const webAuthnStrategy = new WebAuthnStrategy({
    rpID: process.env.RP_ID || "localhost",
    rpName: process.env.RP_NAME || "My WebAuthn App",
    userStore,
    challengeStore,
});

passport.use(webAuthnStrategy);

router.post("/register/challenge", async (req: Request, res: Response) => {
    try {
        const options = await webAuthnStrategy.registerChallenge(req, req.body.username);
        res.json(options);
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

router.post("/register/callback", async (req: Request, res: Response) => {
    try {
        const user = await webAuthnStrategy.registerCallback(req, req.body.username, req.body.credential);
        res.json({ success: true, user });
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

router.post("/login/challenge", async (req: Request, res: Response) => {
    try {
        const options = await webAuthnStrategy.loginChallenge(req, req.body.username);
        res.json(options);
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

router.post("/login/callback", async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, credential } = req.body;
        if (!credential) throw new Error("Missing credential data");

        const user = await webAuthnStrategy.loginCallback(req, username, credential);
        req.login(user, err => {
            if (err) return res.status(500).json({ error: 'Login failed' });
            req.session.save(() => res.json({ success: true }));
        });
    } catch (error) {
        next(error);
    }
});

export default router;