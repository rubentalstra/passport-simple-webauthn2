import express, { Request, Response } from 'express';
import passport from 'passport';
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    WebAuthnCredential,
} from '@simplewebauthn/server';
import { v4 as uuidv4 } from 'uuid';
import {
    bufferToBase64URL,
    serializeAuthenticationOptions,
    serializeRegistrationOptions
} from "../utils";

const router = express.Router();
router.use(express.json());
router.use(express.urlencoded({ extended: true }));

// 🛠️ FIX: Use an in-memory object to store users
const users: Record<string, { userID: string, username: string, passkeys: WebAuthnCredential[] }> = {};
const challenges: Record<string, string> = {};

/**
 * 🔹 Helper function: Get user by username
 */
const getUserByUsername = (username: string) => Object.values(users).find(user => user.username === username);

/**
 * 🔹 Helper function: Get user by ID
 */
const getUserById = (userID: string) => users[userID];

/**
 * 🔹 Passport serialization
 */
passport.serializeUser((user: any, done) => done(null, user.userID));
passport.deserializeUser((userID: string, done) => done(null, getUserById(userID) || false));

/**
 * 🔹 Register Page
 */
router.get('/', (req: Request, res: Response) => {
    res.render('index');
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
    if (!username) return res.status(400).json({ error: 'Username required' });

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
    if (!username || !credential) return res.status(400).json({ error: 'Invalid data' });

    const user = Object.values(users).find((u) => u.username === username);
    if (!user || !challenges[user.userID]) return res.status(400).json({ error: 'Invalid request' });

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
                console.error('Login error:', err);
                return res.status(500).json({ error: 'Login failed' });
            }
            req.session.save((err) => {
                if (err) {
                    console.error('Session save error:', err);
                    return res.status(500).json({ error: 'Session save failed' });
                }
                console.log('Session successfully saved:', req.session);
                res.json({ success: true });
            });
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
    if (!username) return res.status(400).json({ error: 'Username required' });

    const user = Object.values(users).find((u) => u.username === username);
    if (!user) return res.status(400).json({ error: 'User not found' });

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
 * 🔹 WebAuthn Login Callback
 */
router.post('/login-callback', async (req: Request, res: Response) => {
    const { username, credential } = req.body;
    if (!username || !credential) return res.status(400).json({ error: 'Invalid data' });

    const user = getUserByUsername(username);
    if (!user || !challenges[user.userID]) return res.status(400).json({ error: 'Invalid request' });

    const passkey = user.passkeys.find((p) => p.id === bufferToBase64URL(Buffer.from(credential.id, 'base64url').toString('base64url')));
    if (!passkey) return res.status(400).json({ error: 'Passkey not found' });

    try {
        const verification = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge: challenges[user.userID],
            expectedOrigin: `https://${process.env.RP_ID}`,
            expectedRPID: process.env.RP_ID || 'localhost',
            credential: {
                id: passkey.id,
                publicKey: passkey.publicKey,
                counter: passkey.counter,
                transports: passkey.transports,
            },
            requireUserVerification: true,
        });

        if (!verification.verified) {
            return res.status(400).json({ error: 'Verification failed' });
        }

        passkey.counter = verification.authenticationInfo.newCounter;
        delete challenges[user.userID];

        req.login(user, (err) => {
            if (err) return res.status(500).json({ error: 'Login failed' });
            req.session.save(() => res.json({ success: true }));
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
    if (!req.isAuthenticated()) {
        console.log('User is not authenticated. Redirecting...');
        return res.redirect('/login');
    }
    res.render('account', { user: req.user });
});

/**
 * 🔹 Logout
 */
router.get('/logout', (req: Request, res: Response) => {
    req.logout((err) => {
        if (err) return res.status(500).send('Error logging out.');
        req.session.destroy(() => res.redirect('/'));
    });
});

export default router;