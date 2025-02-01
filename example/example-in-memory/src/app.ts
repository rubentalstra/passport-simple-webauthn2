import dotenv from "dotenv";
dotenv.config();

import express, { Request, Response, NextFunction } from "express";
import session from "express-session";
import passport from "passport";
import cors from "cors";
import path from "path";
import { WebAuthnStrategy } from "passport-simple-webauthn2";
import {InMemoryUserStore} from "./store/userStore";
import {InMemoryChallengeStore} from "./store/challengeStore";
import {WebAuthnUser} from "./type"; // Adjust the import path as needed

// ----- In-Memory Store Implementations -----


// ----- End of In-Memory Store Implementations -----


// Create the Express app
const app = express();
const PORT = process.env.PORT || 5000;

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Use cookie-based session storage (Not for production use)
app.use(
    session({
        secret: process.env.SESSION_SECRET || "default_secret",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false, // Set to true in production when using HTTPS
            httpOnly: true,
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000,
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

// Create instances of the in-memory stores
const userStore = new InMemoryUserStore();
const challengeStore = new InMemoryChallengeStore();

// Passport Serialization
passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
    try {
        const user = await userStore.get(id, true);
        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Initialize and use the WebAuthn strategy
passport.use(
    new WebAuthnStrategy({
        rpID: process.env.RP_ID || "yourdomain.com",
        rpName: process.env.RP_NAME || "Your App",
        userStore,
        challengeStore,
        debug: true,
    })
);

// ----- Routes -----

// Home Page
app.get("/", (req: Request, res: Response) => {
    res.render("index");
});

// Registration & Login Views
app.get("/register", (req: Request, res: Response) => {
    res.render("register");
});

app.get("/login", (req: Request, res: Response) => {
    res.render("login");
});

// Registration Challenge Endpoint (GET)
// This route will generate and send registration challenge options.
app.get(
    "/webauthn/register",
    passport.authenticate("webauthn", { session: false }),
    (req, res) => {
        res.json(req.user); // Returns challenge options
    }
);

// Registration Callback Endpoint (POST)
// This route completes the registration.
app.post(
    "/webauthn/register",
    passport.authenticate("webauthn", { session: false }),
    (req, res) => {
        // On success, req.user contains the updated user (with new passkey)
        res.json({ user: req.user });
    }
);

// Login Challenge Endpoint (GET)
app.get(
    "/webauthn/login",
    passport.authenticate("webauthn", { session: false }),
    (req, res) => {
        res.json(req.user); // Returns challenge options
    }
);

// Login Callback Endpoint (POST)
app.post("/webauthn/login", passport.authenticate("webauthn"), (req, res) => {
    // On success, req.user is the authenticated user.
    res.json({ user: req.user });
});

// Account Route: Requires an authenticated user.
app.get("/account", (req: Request, res: Response) => {
    if (!req.isAuthenticated() || !req.user) {
        return res.redirect("/login");
    }
    try {
        res.render("account", { passkeys: (req.user as WebAuthnUser).passkeys });
    } catch (error) {
        console.error("Error loading account:", error);
        res.redirect("/login");
    }
});

// Account Passkeys API Route
app.get("/account/passkeys", (req: Request, res: Response) => {
    if (!req.isAuthenticated() || !req.user) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    try {
        res.json({ passkeys: (req.user as WebAuthnUser).passkeys });
    } catch (err) {
        console.error("Error fetching passkeys:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Logout Route
app.post("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy(() => {
            res.redirect("/");
        });
    });
});

// Start the server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));