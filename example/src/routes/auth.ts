// src/routes/auth.ts
import express, { Request, Response } from "express";
import passport from "passport";
import { generateAuthentication, generateRegistration, verifyRegistration, verifyAuthentication, RegistrationUser, AuthUser } from "passport-simple-webauthn2"; // Replace with your actual package name
import { findUserByUsername, createUser } from "../models/user";

const router = express.Router();

// Registration Initiation
router.post("/register", async (req: Request, res: Response) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Username is required" });

    let user = findUserByUsername(username);
    if (!user) {
        user = createUser(username);
    }

    const registrationOptions = await generateRegistration(req, {
        id: user.id,
        name: username,
        displayName: username,
        credentials: user.credentials,
    });

    res.json(registrationOptions);
});

// Registration Verification
router.post("/register/verify", async (req: Request, res: Response) => {
    const { username, response } = req.body;
    if (!username || !response) return res.status(400).json({ error: "Missing fields" });

    const user = findUserByUsername(username);
    if (!user) return res.status(404).json({ error: "User not found" });

    try {
        const verification = await verifyRegistration(req, user, response);
        if (verification.verified && verification.registrationInfo) {
            const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;

            const newCredential = {
                id: Buffer.from(credentialID).toString("base64url"),
                publicKey: credentialPublicKey,
                user: user,
                webauthnUserID: Buffer.from(user.id).toString("base64url"),
                counter,
                deviceType: "singleDevice",
                backedUp: false,
                transports: response.transports,
            };

            user.credentials.push(newCredential);
        }

        res.json({ verified: verification.verified });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Authentication Initiation
router.post("/login", async (req: Request, res: Response) => {
    try {
        const authOptions = await generateAuthentication(req);
        res.json(authOptions);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Authentication Verification
router.post("/login/verify", passport.authenticate("simple-webauthn"), (req: Request, res: Response) => {
    res.json({ authenticated: true });
});

// Logout
router.post("/logout", (req: Request, res: Response) => {
    req.logout();
    res.json({ loggedOut: true });
});

export default router;