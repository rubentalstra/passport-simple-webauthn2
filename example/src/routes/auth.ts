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
 * Renders the registration HTML page.
 */
router.get('/register', (req: Request, res: Response) => {
    res.render('register'); // Ensure you have a view engine set up
});

/**
 * 🔹 Generate WebAuthn Registration Challenge
 * Generates registration options and sends them to the client.
 */
router.post('/register-challenge', async (req: Request, res: Response) => {
    const { username } = req.body as { username: string };
    if (!username) {
        return res.status(400).json({ error: 'Username required' });
    }

    // Find existing user or create a new one
    let user = Object.values(users).find((u) => u.username === username);
    if (!user) {
        const userID = uuidv4();
        user = { userID, username, passkeys: [] };
        users[userID] = user;
    }

    // Generate registration options
    const options = await generateRegistrationOptions({
        rpName: process.env.RP_NAME || 'WebAuthn Demo',
        rpID: process.env.RP_ID || 'localhost',
        userID: Buffer.from(user.userID, 'utf-8'),
        userName: user.username,
        attestationType: 'none',
        // Exclude already registered credentials
        excludeCredentials: user.passkeys.map((cred) => ({
            id: cred.id, // Convert Base64URL string to Buffer
            type: 'public-key',
            transports: cred.transports,
        })),
        authenticatorSelection: {
            userVerification: 'preferred',
            authenticatorAttachment: 'platform',
        },
    });

    // Store the challenge for this user
    challenges[user.userID] = bufferToBase64URL(options.challenge);

    // Serialize options to send to the client
    const optionsJSON = serializeRegistrationOptions(options);

    // Optional: Log the serialized options for debugging
    console.log('Registration Options Sent to Client:', optionsJSON);

    res.json(optionsJSON);
});

/**
 * 🔹 WebAuthn Register Callback
 * Verifies the registration response and registers the new credential.
 */
router.post('/register-callback', async (req: Request, res: Response) => {
    const { username, credential } = req.body as {
        username: string;
        credential: RegistrationResponseJSON;
    };

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
        // Verify the registration response
        const verification = await verifyRegistrationResponse({
            response: {
                id: credential.id,
                rawId: credential.rawId,
                response: {
                    clientDataJSON: credential.response.clientDataJSON,
                    attestationObject: credential.response.attestationObject,
                },
                type: credential.type,
                clientExtensionResults: credential.clientExtensionResults,
            },
            expectedChallenge: storedChallenge,
            expectedOrigin: `https://${process.env.RP_ID}`, // Ensure this matches your origin
            expectedRPID: process.env.RP_ID || 'localhost',
            requireUserVerification: true,
        });

        if (!verification.verified || !verification.registrationInfo) {
            return res.status(400).json({ error: 'Verification failed' });
        }

        const { publicKey, id, counter, transports } = verification.registrationInfo.credential;

        // Create a new credential record
        const newCredential: WebAuthnCredential = {
            id: bufferToBase64URL(id),
            publicKey: new Uint8Array(publicKey),
            counter: counter,
            transports: transports,
        };

        // Register the new credential with the user
        user.passkeys.push(newCredential);

        // Optional: Log the new credential for debugging
        console.log('New Credential Registered:', newCredential);

        // Log the user in
        req.login(user, (err) => {
            if (err) {
                console.error('Login error:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            res.json({ success: true });
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

/**
 * 🔹 Login Page
 * Renders the login HTML page.
 */
router.get('/login', (req: Request, res: Response) => {
    res.render('login'); // Ensure you have a view engine set up
});

/**
 * 🔹 Generate WebAuthn Authentication Challenge
 * Generates authentication options and sends them to the client.
 */
router.post('/login-challenge', async (req: Request, res: Response) => {
    const { username } = req.body as { username: string };
    if (!username) {
        return res.status(400).json({ error: 'Username required' });
    }

    const user = Object.values(users).find((u) => u.username === username);
    if (!user) {
        return res.status(400).json({ error: 'User not found' });
    }

    // Generate authentication options
    const options = await generateAuthenticationOptions({
        rpID: process.env.RP_ID || 'localhost',
        userVerification: 'discouraged', // Adjust based on your security requirements
        allowCredentials: user.passkeys.map((cred: WebAuthnCredential) => ({
            id: cred.id,
            type: 'public-key',
            transports: cred.transports,
        })),
    });

    // Store the challenge for this user
    challenges[user.userID] = bufferToBase64URL(options.challenge);

    // Serialize options to send to the client
    const optionsJSON = serializeAuthenticationOptions(options);

    // Optional: Log the serialized options for debugging
    console.log('Authentication Options Sent to Client:', optionsJSON);

    res.json(optionsJSON);
});

/**
 * 🔹 Authenticate with WebAuthn
 * Verifies the authentication response and logs the user in.
 */
router.post('/login-callback', async (req: Request, res: Response) => {
    const { username, credential } = req.body as {
        username: string;
        credential: AuthenticationResponseJSON;
    };

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
        // Find the corresponding passkey
        const passkey = user.passkeys.find((p) => p.id === credential.id);
        if (!passkey) {
            return res.status(400).json({ error: 'Passkey not found' });
        }

        // Prepare the response object for verification
        const response: AuthenticationResponseJSON = {
            id: credential.id,
            rawId: credential.rawId,
            response: {
                authenticatorData: credential.response.authenticatorData,
                clientDataJSON: credential.response.clientDataJSON,
                signature: credential.response.signature,
                userHandle: credential.response.userHandle,
            },
            type: credential.type,
            clientExtensionResults: credential.clientExtensionResults,
        };

        // Prepare the WebAuthnCredential object
        const webauthnCredential: WebAuthnCredential = {
            id: passkey.id, // Base64URL string
            publicKey: passkey.publicKey, // Uint8Array
            counter: passkey.counter,
            transports: passkey.transports,
        };

        // Verify the authentication response
        const verification = await verifyAuthenticationResponse({
            response: response,
            expectedChallenge: storedChallenge,
            expectedOrigin: `https://${process.env.RP_ID}`, // Ensure this matches your origin
            expectedRPID: process.env.RP_ID || 'localhost',
            credential: webauthnCredential,
            requireUserVerification: true,
        });

        if (!verification.verified || !verification.authenticationInfo) {
            return res.status(400).json({ error: 'Verification failed' });
        }

        // Update the counter to prevent replay attacks
        passkey.counter = verification.authenticationInfo.newCounter;

        // Optional: Log the verification info for debugging
        console.log('Authentication Verified:', verification.authenticationInfo);

        // Log the user in
        req.login(user, (err) => {
            if (err) {
                console.error('Login error:', err);
                return res.status(500).json({ error: 'Internal Server Error' });
            }
            res.json({ success: true });
        });
    } catch (error) {
        console.error('Authentication error:', error);
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
 * Logs the user out and redirects to the home page.
 */
router.get('/logout', (req: Request, res: Response) => {
    req.logout((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).send('Error logging out.');
        }
        res.redirect('/');
    });
});

export default router;