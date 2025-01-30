import express, { Request, Response } from "express";
import passport from "passport";
import {
    generateAuthentication,
    generateRegistration,
    verifyRegistration,
    Passkey,
} from "passport-simple-webauthn2";
import type { WebAuthnCredential, RegistrationResponseJSON } from "@simplewebauthn/server";

const router = express.Router();

/**
 * **[1] Registration Initiation**
 * - Uses `req.user` to register the authenticated user.
 * - Generates WebAuthn registration options.
 */
// @ts-ignore
router.post("/register", async (req: Request, res: Response) => {
    // if (!req.user) return res.status(401).json({ error: "User not authenticated" });

    try {
        const registrationOptions = await generateRegistration(req);
        res.json(registrationOptions);
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * **[2] Registration Verification**
 * - Verifies WebAuthn response and stores credential.
 */
// @ts-ignore
router.post("/register/verify", async (req: Request, res: Response) => {
    if (!req.user) return res.status(401).json({ error: "User not authenticated" });

    const { response } = req.body;
    if (!response) return res.status(400).json({ error: "Missing WebAuthn response" });

    try {
        const verification = await verifyRegistration(req, response as RegistrationResponseJSON);

        response.counter
        if (verification.verified && verification.registrationInfo) {
            const newCredential: WebAuthnCredential = {
                id: response.credentialID,
                publicKey: response.credentialPublicKey,
                counter: response.counter,
                transports: response.transports || [],
            };

            (req.user as any).credentials.push(newCredential as Passkey);
        }

        res.json({ verified: verification.verified });
    } catch (error: any) {
        res.status(400).json({ error: error.message });
    }
});


/**
 * **[3] Authentication Initiation**
 * - Uses `req.user` to generate authentication options.
 */
// @ts-ignore
router.post("/login", async (req: Request, res: Response) => {
    if (!req.user) return res.status(401).json({ error: "User not authenticated" });

    try {
        const authOptions = await generateAuthentication(req);
        res.json(authOptions);
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * **[4] Authentication Verification**
 * - Uses Passport middleware to authenticate via WebAuthn.
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