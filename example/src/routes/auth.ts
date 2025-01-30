// src/routes/auth.ts
import express, { Request, Response } from "express";
import passport from "passport";
import {
    generateAuthentication,
    generateRegistration,
    verifyRegistration,
    RegistrationUser, Passkey,
} from "passport-simple-webauthn2";
import { findUserByUsername, createUser } from "../models/user";
import type {
    WebAuthnCredential,
} from "@simplewebauthn/server";
import type {
    RegistrationResponseJSON,
} from "@simplewebauthn/server";

const router = express.Router();

// Registration Initiation
// @ts-ignore
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
    } as RegistrationUser);

    res.json(registrationOptions);
});


// Registration Verification
// @ts-ignore
router.post("/register/verify", async (req: Request, res: Response) => {
    const { username, response } = req.body;
    if (!username || !response) return res.status(400).json({ error: "Missing fields" });

    const user = findUserByUsername(username);
    if (!user) return res.status(404).json({ error: "User not found" });

    try {
        const verification = await verifyRegistration(req, {
            id: user.id,
            name: user.username,
            displayName: user.username,
            credentials: user.credentials,
        } as RegistrationUser, response as RegistrationResponseJSON);

        if (verification.verified && verification.registrationInfo) {
            const { credential } = verification.registrationInfo;

            // Destructure properties from the credential object
            const { publicKey, id, counter } = credential;

            const newCredential: WebAuthnCredential = {
                id,
                publicKey,
                counter,
                transports: response.transports,
            };

            user.credentials.push(newCredential as Passkey);
        }

        res.json({ verified: verification.verified });
    } catch (error: any) {
        res.status(400).json({ error: error.message });
    }
});


// Authentication Initiation
router.post("/login", async (req: Request, res: Response) => {
    try {
        const authOptions = await generateAuthentication(req);
        res.json(authOptions);
    } catch (error: any) {
        res.status(400).json({ error: error.message });
    }
});

// Authentication Verification
router.post(
    "/login/verify",
    passport.authenticate("simple-webauthn", { failureRedirect: "/login-failure" }),
    (req: Request, res: Response) => {
        res.json({ authenticated: true });
    }
);

// Logout
router.post("/logout", (req: Request, res: Response) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ error: "Failed to logout." });
        }
        res.json({ loggedOut: true });
    });
});

// Login Failure Route
router.get("/login-failure", (req: Request, res: Response) => {
    res.status(401).json({ error: "Authentication failed." });
});

export default router;