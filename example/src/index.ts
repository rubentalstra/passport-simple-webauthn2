import express from 'express';
import session from 'express-session';
import passport from 'passport';
import path from 'path';
import bodyParser from 'body-parser';
import dotenv from 'dotenv';
import { users, passkeys, userCredentialMap } from './store/store';
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { clearChallenge, getChallenge, saveChallenge } from "./challengeStore";
import {
    generateRegistration,
    Passkey,
    SimpleWebAuthnStrategy,
    SimpleWebAuthnStrategyOptions,
    verifyAuthentication,
    verifyRegistration
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
passport.serializeUser((userID: string, done) => {
    done(null, userID);
});

passport.deserializeUser((userID: string, done) => {
    console.log(`🔄 [Deserialize] Looking up user with ID: ${userID}`);
    if (users.has(userID)) {
        console.log(`✅ [Deserialize] User found`);
        done(null, userID);
    } else {
        console.error(`❌ [Deserialize] User not found for ID: ${userID}`);
        done(new Error('User not found'), null);
    }
});

// WebAuthn Strategy Options
const strategyOptions: SimpleWebAuthnStrategyOptions = {
    findPasskeyByCredentialID: async (credentialID: string) => passkeys.get(credentialID) || null,
    updatePasskeyCounter: async (credentialID: string, newCounter: number) => {
        const passkey = passkeys.get(credentialID);
        if (passkey) {
            passkey.counter = newCounter;
            passkeys.set(credentialID, passkey);
        }
    },
    findUserIDByWebAuthnID: async (webauthnUserID: string) => {
        return userCredentialMap.get(webauthnUserID) || null;
    },
    registerPasskey: async (userID: string, passkey: Passkey) => {
        passkeys.set(passkey.id, passkey);
        userCredentialMap.set(passkey.webauthnUserID, userID);
    },
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
        console.log("📩 [Register] Incoming request:", req.body);
        const { username } = req.body;
        if (!username) return res.status(400).json({ error: 'Username is required' });

        // Generate a base64url-encoded user ID
        const userID = Buffer.from(username).toString('base64url');
        console.log(`🆕 [Register] Creating user with ID: ${userID}`);

        users.set(userID, { id: userID, username });

        // Generate WebAuthn registration options
        const registrationOptions = await generateRegistration(userID, username);
        console.log("📡 [Register] Registration options generated:", registrationOptions);

        // Save challenge using user ID
        await saveChallenge(userID, registrationOptions.challenge);

        res.json(registrationOptions);
    } catch (error) {
        console.error("❌ [Register] Error:", error);
        next(error);
    }
});

// Registration - Callback
app.post('/register/callback', async (req, res, next) => {
    try {
        console.log("📩 [Register Callback] Received:", req.body);
        const { response, username } = req.body;
        if (!response || !username) {
            return res.status(400).json({ error: "Invalid registration response" });
        }

        const userID = Buffer.from(username).toString('base64url');
        const expectedChallenge = await getChallenge(userID);

        if (!expectedChallenge) {
            console.error("❌ [Register Callback] Challenge not found for user:", username);
            return res.status(400).json({ error: "Challenge expired or not found" });
        }

        // Verify WebAuthn registration
        const verification = await verifyRegistration(
            response,
            expectedChallenge,
            strategyOptions.findUserIDByWebAuthnID,
            strategyOptions.registerPasskey
        );

        console.log("✅ [Register Callback] Verification Result:", verification);

        if (!verification.verified) {
            return res.status(400).json({ error: "Verification failed" });
        }

        await clearChallenge(userID);
        res.json({ success: true, message: "Registration successful" });
    } catch (error) {
        console.error("❌ [Register Callback] Error:", error);
        res.status(500).json({ error: "Server error during registration" });
    }
});

// Login - Generate Options
app.post('/login/options', async (req, res) => {
    try {
        const { username } = req.body;
        const userID = Buffer.from(username).toString('base64url');

        if (!users.has(userID)) return res.status(400).json({ error: "User not found" });

        // Generate authentication options
        const options = await generateAuthenticationOptions({
            rpID: process.env.RP_ID || 'default-rp-id',
            allowCredentials: Array.from(passkeys.values())
                .filter(pk => pk.userID === userID)
                .map(pk => ({ id: pk.id })),
        });

        await saveChallenge(userID, options.challenge);
        res.json(options);
    } catch (error) {
        console.error("❌ [Login Options] Error:", error);
        res.status(500).json({ error: "Failed to generate login options" });
    }
});

// Login - Authentication
app.post('/login', async (req, res, next) => {
    try {
        console.log("📩 [Login] Incoming request:", req.body);
        const { username, response } = req.body;
        if (!username || !response) return res.status(400).send("Missing username or response");

        const userID = Buffer.from(username).toString('base64url');
        const expectedChallenge = await getChallenge(userID);

        if (!expectedChallenge) {
            console.error("❌ [Login] Challenge not found for user:", username);
            return res.status(400).send("Challenge expired or not found");
        }

        // Verify authentication
        const verification = await verifyAuthentication(
            response,
            expectedChallenge,
            strategyOptions.findPasskeyByCredentialID,
            strategyOptions.updatePasskeyCounter
        );

        console.log("✅ [Login] Verification Result:", verification);

        if (!verification.verified) {
            return res.status(400).json({ error: "Authentication failed" });
        }

        await clearChallenge(userID);
        res.redirect('/dashboard');
    } catch (error) {
        console.error("❌ [Login] Error:", error);
        next(error);
    }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));