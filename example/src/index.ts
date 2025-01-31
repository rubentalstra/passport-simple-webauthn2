// src/index.ts

import express from 'express';
import session from 'express-session';
import passport from 'passport';
import path from 'path';
import bodyParser from 'body-parser';
import { users, passkeys } from './store';
import {
    generateRegistration,
    SimpleWebAuthnStrategy,
    registration,
    UserModel,
    Passkey, SimpleWebAuthnStrategyOptions
} from "passport-simple-webauthn2";
import dotenv from 'dotenv';

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
    secret: 'your-secret-key', // Replace with a secure secret
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
        return passkeys.get(credentialID) || null;
    },
    updatePasskeyCounter: async (credentialID: string, newCounter: number) => {
        const passkey = passkeys.get(credentialID);
        if (passkey) {
            passkey.counter = newCounter;
            passkeys.set(credentialID, passkey);
        }
    },
    findUserByWebAuthnID: async (webauthnUserID: string) => {
        return users.get(webauthnUserID) || null;
    },
    registerPasskey: async (user: UserModel, passkey: Passkey) => {
        passkeys.set(passkey.id, passkey);
    },
};

// Configure Passport to use the SimpleWebAuthnStrategy
passport.use(new SimpleWebAuthnStrategy(strategyOptions));

// Routes

// Home Route
app.get('/', (req, res) => {
    res.render('login');
});

// Registration Route - GET
app.get('/register', (req, res) => {
    res.render('register');
});

// Registration Route - POST
app.post('/register', async (req, res, next) => {
    try {
        const { username } = req.body;
        if (!username) {
            return res.status(400).send('Username is required');
        }

        // Create a new user
        const user: UserModel = {
            id: Buffer.from(username).toString('base64url'), // Base64URLString
            username,
        };
        users.set(user.id, user);

        // Generate registration options
        const { generateRegistrationOptions } = await import('@simplewebauthn/server');
        const registrationOptions = await generateRegistration(user);

        res.json(registrationOptions);
    } catch (error) {
        next(error);
    }
});

// Registration Callback Route
app.post('/register/callback', async (req, res, next) => {
    try {
        const { response, username } = req.body;
        if (!response || !username) {
            return res.status(400).send('Invalid registration response');
        }

        // Find user
        const user = Array.from(users.values()).find(u => u.username === username);
        if (!user) {
            return res.status(400).send('User not found');
        }

        // Register the passkey
        await registration(response, async (webauthnUserID: string) => {
            return users.get(webauthnUserID) || null;
        }, async (user: UserModel, passkey: Passkey) => {
            passkeys.set(passkey.id, passkey);
        });

        res.send('Registration successful');
    } catch (error) {
        next(error);
    }
});

// Login Route - GET
app.get('/login', (req, res) => {
    res.render('login');
});

// Login Route - POST
app.post('/login', passport.authenticate('simple-webauthn'), (req, res) => {
    res.redirect('/dashboard');
});

// Dashboard Route - Protected
app.get('/dashboard', isAuthenticated, (req, res) => {
    res.render('dashboard', { user: req.user });
});

// Logout Route
app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

// Middleware to check authentication
function isAuthenticated(req: express.Request, res: express.Response, next: express.NextFunction) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Error Handling Middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start the Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});