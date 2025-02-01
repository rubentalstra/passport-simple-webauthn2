import express, { Request, Response } from "express";
import passport from "passport";
import { MongoUserStore } from "../stores/MongoUserStore";
import { MongoChallengeStore } from "../stores/MongoChallengeStore";
// @ts-ignore
import { WebAuthnStrategy } from "../../../dist/index";

const router = express.Router();
const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

const webAuthnStrategy = new WebAuthnStrategy({
    rpID: process.env.RP_ID || "localhost",
    rpName: process.env.RP_NAME || "My WebAuthn App",
    userStore,
    challengeStore,
    debug: true,
});

passport.use(webAuthnStrategy);

/**
 * Generate a registration challenge.
 */
router.post("/register/challenge", async (req: Request, res: Response) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ error: "Username is required" });
        }

        const options = await webAuthnStrategy.registerChallenge(req, username);
        res.json(options);
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

/**
 * Handle the registration callback.
 */
router.post("/register/callback", async (req: Request, res: Response) => {
    try {
        const { username, credential } = req.body;
        if (!username || !credential) {
            return res.status(400).json({ error: "Username and credential are required" });
        }

        const { passkeys } = await webAuthnStrategy.registerCallback(req, username, credential);
        await userStore.updatePasskeys(username, passkeys);

        res.json({ success: true });
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

/**
 * Generate a login challenge.
 */
router.post("/login/challenge", async (req: Request, res: Response) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).json({ error: "Username is required" });
        }

        const options = await webAuthnStrategy.loginChallenge(req, username);
        res.json(options);
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

/**
 * Handle the login callback.
 */
router.post("/login/callback", async (req: Request, res: Response, next) => {
    try {
        const { username, credential } = req.body;
        if (!username || !credential) {
            return res.status(400).json({ error: "Username and credential are required" });
        }

        const { verified, counter } = await webAuthnStrategy.loginCallback(req, username, credential);
        if (!verified) {
            return res.status(401).json({ error: "Authentication failed" });
        }

        // Securely fetch user by username
        const user = await userStore.get(username);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Securely update the passkey counter
        await userStore.updatePasskeyCounter(user.username, credential.id, counter);

        // Authenticate user and persist session securely
        req.login(user, (err) => {
            if (err) return next(err);
            req.session.save((sessionErr) => {
                if (sessionErr) return next(sessionErr);
                res.json({ success: true, user });
            });
        });
    } catch (err: any) {
        next(err);
    }
});

export default router;