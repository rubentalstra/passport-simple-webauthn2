import express from 'express';
import session from 'express-session';
import passport from 'passport';
import path from 'path';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import { users, passkeys } from './store/store';
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import {clearChallenge, getChallenge, saveChallenge} from "./challengeStore";
import {
    generateRegistration,
    Passkey,
    SimpleWebAuthnStrategy,
    SimpleWebAuthnStrategyOptions,
    UserModel, verifyAuthentication, verifyRegistration
} from "passport-simple-webauthn2";

// Load environment variables
dotenv.config();

const app = express();

// Middleware Setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '../views'));
app.use(express.static(path.join(__dirname, '../public')));

// Session Setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Define Passport Serialization
passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

passport.deserializeUser((id: string, done) => {
    const user = users.get(id);
    if (user) {
        done(null, user);
    } else {
        done(new Error('User not found'), null);
    }
});

// Define Strategy Options
const strategyOptions: SimpleWebAuthnStrategyOptions = {
    findPasskeyByCredentialID: async (credentialID: string) => {
        const decodedCredentialID = Buffer.from(credentialID, 'base64url').toString('utf-8');
        return passkeys.get(decodedCredentialID) || null;
    },
    updatePasskeyCounter: async (credentialID: string, newCounter: number) => {
        const passkey = passkeys.get(credentialID);
        if (passkey) {
            passkey.counter = newCounter;
            passkeys.set(credentialID, passkey);
        }
    },
    findUserByWebAuthnID: async (webauthnUserID: string) => {
        const decodedUserId = Buffer.from(webauthnUserID, 'base64url').toString('utf-8');
        return users.get(decodedUserId) || null;
    },
    registerPasskey: async (user: UserModel, passkey: Passkey) => passkeys.set(passkey.id, passkey),
};

// Configure Passport to use SimpleWebAuthnStrategy
passport.use(new SimpleWebAuthnStrategy(strategyOptions));

// Routes

// Home Page
app.get('/', (req, res) => {
    res.render('index');
});

// Registration Page
app.get('/register', (req, res) => {
    res.render('register');
});

// Registration - Generate Options
app.post('/register', async (req, res, next) => {
    try {
        const { username } = req.body;
        if (!username) return res.status(400).send('Username is required');

        // Generate a base64url-encoded user ID
        const userId = Buffer.from(username).toString('base64url');

        const user: UserModel = { id: userId, username };
        users.set(user.id, user);

        // Generate WebAuthn registration options
        const registrationOptions = await generateRegistration(user);

        // Save challenge using user.id instead of username
        await saveChallenge(user.id, registrationOptions.challenge);

        res.json(registrationOptions);
    } catch (error) {
        next(error);
    }
});

// Registration - Callback
app.post('/register/callback', async (req, res, next) => {
    try {
        const { response, username } = req.body;
        if (!response || !username) {
            return res.status(400).json({ error: "Invalid registration response" });
        }

        // Retrieve user by ID (since challenges are stored with user ID)
        const userId = Buffer.from(username).toString('base64url');
        const expectedChallenge = await getChallenge(userId);

        if (!expectedChallenge) {
            return res.status(400).json({ error: "Challenge expired or not found" });
        }

        console.log("Received registration callback:", response);

        // Verify WebAuthn registration
        const verification = await verifyRegistration(
            response,
            expectedChallenge,
            strategyOptions.findUserByWebAuthnID,
            strategyOptions.registerPasskey
        );

        if (!verification.verified) {
            return res.status(400).json({ error: "Verification failed" });
        }

        // Clear the challenge after successful verification
        await clearChallenge(userId);
        res.json({ success: true, message: "Registration successful" });
    } catch (error) {
        console.error("Error during registration callback:", error);
        res.status(500).json({ error: "Server error during registration" });
    }
});

// Login Page
app.get('/login', (req, res) => {
    res.render('login');
});

// Login - Generate Options
app.post('/login/options', async (req, res) => {
    const { username } = req.body;
    const user = Array.from(users.values()).find(u => u.username === username);

    if (!user) return res.status(400).json({ error: "User not found" });

    // Generate authentication options
    const options = await generateAuthenticationOptions({
        rpID: process.env.RP_ID || 'default-rp-id',
        allowCredentials: Array.from(passkeys.values())
            .filter(pk => pk.user.id === user.id)
            .map(pk => ({ id: pk.id })),
    });

    // Save challenge using user.id instead of username
    await saveChallenge(user.id, options.challenge);
    res.json(options);
});

// Login - Authentication
app.post('/login', async (req, res, next) => {
    try {
        const { username, response } = req.body;
        if (!username || !response) return res.status(400).send("Missing username or response");

        // Retrieve user ID from username
        const userId = Buffer.from(username).toString('base64url');

        // Retrieve challenge using user ID
        const expectedChallenge = await getChallenge(userId);
        if (!expectedChallenge) {
            return res.status(400).send("Challenge expired or not found");
        }

        // Verify authentication
        const verification = await verifyAuthentication(
            response,
            expectedChallenge,
            strategyOptions.findPasskeyByCredentialID,
            strategyOptions.updatePasskeyCounter
        );

        if (!verification.verified) {
            return res.status(400).json({ error: "Authentication failed" });
        }

        await clearChallenge(userId);
        res.redirect('/dashboard');
    } catch (error) {
        next(error);
    }
});

// Protected Dashboard Route
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.user });
});

// Logout Route
app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});

// Middleware to check authentication
function isAuthenticated(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

// Error Handling Middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));