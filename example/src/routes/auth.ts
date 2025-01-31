// router.ts
import express, { Request, Response } from 'express';
import session from 'express-session';
import passport from 'passport';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    RegistrationResponseJSON,
    WebAuthnCredential,
    AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { v4 as uuidv4 } from 'uuid';
import { User } from "../types";
import {
    bufferToBase64URL,
    serializeAuthenticationOptions,
    serializeRegistrationOptions
} from "../utils";

const router = express.Router();
router.use(express.json());

// Temporary in-memory storage (use a persistent database in production)
const challenges: Record<string, string> = {};
const users: Record<string, User> = {};

// Session middleware setup
router.use(
    session({
        secret: 'your_secret_key', // Replace with a strong secret in production
        resave: false,
        saveUninitialized: false,
        cookie: { secure: true }, // Set to true if using HTTPS
    })
);

// Initialize Passport (optional, remove if not using Passport elsewhere)
router.use(passport.initialize());
router.use(passport.session());

// Passport serialization (optional, remove if not using Passport)
passport.serializeUser((user: any, done) => {
    done(null, user.userID);
});

passport.deserializeUser((userID: string, done) => {
    const user = users[userID];
    if (user) {
        done(null, user);
    } else {
        done(null, null);
    }
});

/**
 * 🔹 Register Page
 */
router.get('/register', (req: Request, res: Response) => {
    res.render('register');
});

/**
 * 🔹 Generate WebAuthn Registration Challenge
 */
router.post('/register-challenge', async (req: Request, res: Response) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ error: 'Username required' });
    }

    let user = Object.values(users).find((u) => u.username === username);
    if (!user) {
        const userID = uuidv4();
        user = { userID, username, passkeys: [] };
        users[userID] = user;
    }

    const options = await generateRegistrationOptions({
        rpName: process.env.RP_NAME || 'WebAuthn Demo',
        rpID: process.env.RP_ID || 'localhost',
        userID: Buffer.from(user.userID, 'utf-8'),
        userName: user.username,
        attestationType: 'none',
        excludeCredentials: user.passkeys.map((cred) => ({
            id: Buffer.from(cred.id, 'base64url').toString('base64url'),
            type: 'public-key',
            transports: cred.transports || ['internal', 'usb', 'ble', 'nfc'],
        })),
        authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'required',
            authenticatorAttachment: 'platform',
        },
    });

    challenges[user.userID] = bufferToBase64URL(options.challenge);
    res.json(serializeRegistrationOptions(options));
});

/**
 * 🔹 WebAuthn Register Callback
 */
router.post('/register-callback', async (req: Request, res: Response) => {
    const { username, credential } = req.body;

    if (!username || !credential) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    const user = Object.values(users).find((u) => u.username === username);
    if (!user || !challenges[user.userID]) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    const storedChallenge = challenges[user.userID];
    delete challenges[user.userID];

    try {
        const verification = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge: storedChallenge,
            expectedOrigin: `https://${process.env.RP_ID}`,
            expectedRPID: process.env.RP_ID || 'localhost',
            requireUserVerification: true,
        });

        if (!verification.verified || !verification.registrationInfo) {
            return res.status(400).json({ error: 'Verification failed' });
        }

        const { publicKey, id, counter, transports } = verification.registrationInfo.credential;

        const newCredential: WebAuthnCredential = {
            id: bufferToBase64URL(id),
            publicKey: new Uint8Array(publicKey),
            counter,
            transports,
        };

        users[user.userID].passkeys.push(newCredential);
        console.log("Updated user data:", users[user.userID]);

        req.login(user, (err) => {
            if (err) {
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            res.json({ success: true });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

/**
 * 🔹 Login Page
 */
router.get('/login', (req: Request, res: Response) => {
    res.render('login');
});

/**
 * 🔹 Generate WebAuthn Authentication Challenge
 */
router.post('/login-challenge', async (req: Request, res: Response) => {
    const { username } = req.body;
    if (!username) {
        return res.status(400).json({ error: 'Username required' });
    }

    const user = Object.values(users).find((u) => u.username === username);
    if (!user) {
        return res.status(400).json({ error: 'User not found' });
    }

    const platformCredentials = user.passkeys.filter(cred => cred.transports?.includes('internal'));

    const options = await generateAuthenticationOptions({
        rpID: process.env.RP_ID || 'localhost',
        userVerification: 'required',
        allowCredentials: platformCredentials.length > 0 ? platformCredentials.map(cred => ({
            id: Buffer.from(cred.id, 'base64url').toString('base64url'),
            type: 'public-key',
            transports: cred.transports,
        })) : undefined,
    });

    challenges[user.userID] = bufferToBase64URL(options.challenge);
    res.json(serializeAuthenticationOptions(options));
});

/**
 * 🔹 Authenticate with WebAuthn
 */
router.post('/login-callback', async (req: Request, res: Response) => {
    const { username, credential } = req.body;

    if (!username || !credential) {
        return res.status(400).json({ error: 'Invalid data' });
    }

    const user = Object.values(users).find((u) => u.username === username);
    if (!user || !challenges[user.userID]) {
        return res.status(400).json({ error: 'Invalid request' });
    }

    const storedChallenge = challenges[user.userID];
    delete challenges[user.userID];

    console.log("Available passkeys for user:", user.passkeys);
    console.log("Credential ID received:", credential.id);

    const passkey = user.passkeys.find((p) => bufferToBase64URL(Buffer.from(p.id, 'base64url').toString('base64url')) === credential.id);

    if (!passkey) {
        return res.status(400).json({ error: 'Passkey not found' });
    }

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge: storedChallenge,
            expectedOrigin: `https://${process.env.RP_ID}`,
            expectedRPID: process.env.RP_ID || 'localhost',
            credential: passkey,
            requireUserVerification: true,
        });

        if (!verification.verified) {
            return res.status(400).json({ error: 'Verification failed' });
        }

        passkey.counter = verification.authenticationInfo.newCounter;

        req.login(user, (err) => {
            if (err) {
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            res.json({ success: true });
        });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

/**
 * 🔹 Account Page
 * Renders the account page for authenticated users.
 */
router.get('/account', (req: Request, res: Response) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    res.render('account', { user: req.user }); // Ensure you have a view engine set up
});

/**
 * 🔹 Logout
 */
router.get('/logout', (req: Request, res: Response) => {
    req.logout((err) => {
        if (err) return res.status(500).send('Error logging out.');
        res.redirect('/');
    });
});

export default router;