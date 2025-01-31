import express, { Request, Response } from "express";
import passport from "passport";
import {
    generateRegistration, UserModel,
    verifyRegistration,
} from "passport-simple-webauthn2";
import {findUserByUsername, createUser, findUserById} from "../models/User";
import {generateAuthenticationOptions} from "@simplewebauthn/server";

const router = express.Router();

/**
 * **[1] User Signup**
 * - Creates a new user.
 */
// @ts-ignore
router.post("/signup", (req: Request, res: Response) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: "Username is required" });

    let user = findUserByUsername(username);
    if (user) return res.status(409).json({ error: "Username already exists" });

    user = createUser(username);
    req.login(user, (err) => {
        if (err) return res.status(500).json({ error: "Signup failed" });
        res.json({ user });
    });
});

/**
 * **[2] Registration Initiation**
 * - Uses `req.user` to register the authenticated user.
 */
// @ts-ignore
router.post("/register", async (req: Request, res: Response) => {
    if (!req.user) return res.status(401).json({ error: "User not authenticated" });

    try {
        const registrationOptions = await generateRegistration(<UserModel>req.user);
        res.json(registrationOptions);
    } catch (error: any) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * **[3] Registration Verification**
 */
// @ts-ignore
router.post("/register/verify", async (req: Request, res: Response) => {
    if (!req.user) return res.status(401).json({ error: "User not authenticated" });

    const { response } = req.body;
    if (!response) return res.status(400).json({ error: "Missing WebAuthn response" });

    try {
        const verification = await verifyRegistration(response, findUserById, async (passkey) => {
            (req.user as any).credentials.push(passkey);
        });

        res.json({ verified: verification.verified });
    } catch (error: any) {
        res.status(400).json({ error: error.message });
    }
});

/**
 * **[4] Authentication Initiation**
 */
// @ts-ignore
// router.post("/login", async (req: Request, res: Response) => {
//     const { username } = req.body;
//     const user = findUserByUsername(username);
//     if (!user) return res.status(404).json({ error: "User not found" });
//
//     req.login(user, async (err) => {
//         if (err) return res.status(500).json({ error: "Login failed" });
//
//         try {
//             const authOptions = await generateAuthenticationOptions(user.credentials);
//             res.json(authOptions);
//         } catch (error: any) {
//             res.status(500).json({ error: error.message });
//         }
//     });
// });

/**
 * **[5] Authentication Verification**
 */
router.post("/login/verify", passport.authenticate("simple-webauthn"), (req, res) => {
    res.json({ authenticated: true });
});

/**
 * **[6] Logout**
 */
router.post("/logout", (req, res) => {
    req.logout((err) => {
        if (err) return res.status(500).json({ error: "Failed to logout." });
        res.json({ loggedOut: true });
    });
});

export default router;