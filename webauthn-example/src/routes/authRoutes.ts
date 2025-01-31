import express, { Request, Response } from "express";
import passport from "passport";
import { WebAuthnStrategy } from "passport-simple-webauthn2";
import { MongoUserStore } from "../stores/MongoUserStore";
import { MongoChallengeStore } from "../stores/MongoChallengeStore";

const router = express.Router();
const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

passport.use(
    new WebAuthnStrategy({
        rpID: process.env.RP_ID || "localhost",
        rpName: process.env.RP_NAME || "My WebAuthn App",
        userStore,
        challengeStore,
    })
);

router.post("/register/challenge", async (req: Request, res: Response) => {
    try {
        const options = await passport._strategies.webauthn.registerChallenge(req, req.body.username);
        res.json(options);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post("/register/callback", async (req: Request, res: Response) => {
    try {
        const user = await passport._strategies.webauthn.registerCallback(req, req.body.username, req.body.credential);
        res.json({ success: true, user });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post("/login/challenge", async (req: Request, res: Response) => {
    try {
        const options = await passport._strategies.webauthn.loginChallenge(req, req.body.username);
        res.json(options);
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

router.post("/login/callback", async (req: Request, res: Response) => {
    try {
        const user = await passport._strategies.webauthn.loginCallback(req, req.body.username, req.body.credential);
        res.json({ success: true, user });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

export default router;