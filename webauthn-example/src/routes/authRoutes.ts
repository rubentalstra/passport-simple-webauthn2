import express, {NextFunction, Request, Response} from "express";
import passport from "passport";
import { WebAuthnStrategy } from "passport-simple-webauthn2";
import { MongoUserStore } from "../stores/MongoUserStore";
import { MongoChallengeStore } from "../stores/MongoChallengeStore";

const router = express.Router();
const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

// Store a reference to the strategy instance
const webAuthnStrategy = new WebAuthnStrategy({
    rpID: process.env.RP_ID || "localhost",
    rpName: process.env.RP_NAME || "My WebAuthn App",
    userStore,
    challengeStore,
});

// Register the strategy with passport
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


router.post("/login-callback", async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, credential } = req.body;
        if (!credential) {
            throw new Error("Missing credential data");
        }

        // Verify the login response
        const user = await webAuthnStrategy.loginCallback(req, username, credential);

        // Establish a Passport session
        req.login(user, (err) => {
            if (err) return next(err);
            res.json({ success: true, user });
        });
    } catch (error) {
        next(error);
    }
});

export default router;