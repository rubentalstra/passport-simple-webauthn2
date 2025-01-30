import express, { Request, Response } from "express";
import passport from "passport";
import {
    generateAuthentication,
    generateRegistration,
    verifyRegistration,
    RegistrationUser,
    Passkey,
} from "passport-simple-webauthn2";
import { findUserByUsername, createUser } from "../models/user";
import type { WebAuthnCredential, RegistrationResponseJSON } from "@simplewebauthn/server";

const router = express.Router();

/**
 * **[1] Registration Initiation**
 * - Checks if the username exists.
 * - Generates WebAuthn registration options.
 */
router.post("/register", async (req: Request, res: Response) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Username is required" });

    let user = findUserByUsername(username);
    if (!user) {
        user = createUser(username);
    }

    try {
        const registrationOptions = await generateRegistration(req, {
            id: Buffer.from(user.id).toString("base64url"),
            name: user.username,
            displayName: user.username,
            credentials: user.credentials,
        } as RegistrationUser);

        res.json(registrationOptions);
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * **[2] Registration Verification**
 * - Verifies the response from the authenticator.
 * - Saves the credential to the user’s account.
 */
router.post("/register/verify", async (req: Request, res: Response) => {
    const { username, response } = req.body;
    if (!username || !response) return res.status(400).json({ error: "Missing fields" });

    const user = findUserByUsername(username);
    if (!user) return res.status(404).json({ error: "User not found" });

    try {
        const verification = await verifyRegistration(
            req,
            {
                id: Buffer.from(user.id).toString("base64url"),
                name: user.username,
                displayName: user.username,
                credentials: user.credentials,
            } as RegistrationUser,
            response as RegistrationResponseJSON
        );

        if (verification.verified && verification.registrationInfo) {
            const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;

            const newCredential: WebAuthnCredential = {
                id: credentialID,
                publicKey: credentialPublicKey,
                counter,
                transports: response.transports || [],
            };

            user.credentials.push(newCredential as Passkey);
        }

        res.json({ verified: verification.verified });
    } catch (error: any) {
        res.status(400).json({ error: error.message });
    }
});

/**
 * **[3] Authentication Initiation**
 * - Generates authentication options for the user.
 */
router.post("/login", async (req: Request, res: Response) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Username is required" });

    const user = findUserByUsername(username);
    if (!user) return res.status(404).json({ error: "User not found" });

    try {
        const authOptions = await generateAuthentication(req, user);
        res.json(authOptions);
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * **[4] Authentication Verification**
 * - Uses Passport to verify WebAuthn authentication.
 */
router.post("/login/verify", passport.authenticate("simple-webauthn"), (req, res) => {
    res.json({ authenticated: true });
});

/**
 * **[5] Logout**
 * - Ends the user session.
 */
router.post("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).json({ error: "Failed to logout." });
        }
        res.json({ loggedOut: true });
    });
});

/**
 * **[6] Login Failure Route**
 * - Handles failed authentication attempts.
 */
router.get("/login-failure", (req, res) => {
    res.status(401).json({ error: "Authentication failed." });
});

export default router;