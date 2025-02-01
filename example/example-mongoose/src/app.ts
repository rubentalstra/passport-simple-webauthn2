import dotenv from "dotenv";
dotenv.config();

import express, { Request, Response, NextFunction } from "express";
import mongoose from "mongoose";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import path from "path";
import { MongoUserStore } from "./stores/MongoUserStore";
import {MongoChallengeStore} from "./stores/MongoChallengeStore";
import { WebAuthnStrategy } from "../../../dist";
import {User} from "./models/User";

const app = express();
const PORT = process.env.PORT || 5000;

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../src/views"));

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
            secure: false, // Set to true in production with HTTPS
            httpOnly: true,
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000,
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

const userStore = new MongoUserStore();
const challengeStore = new MongoChallengeStore();

// Serialize and deserialize users properly
// Assuming your userStore has a method to retrieve a user by ID.
passport.serializeUser((user: any, done) => {
    done(null, user.userID);
});

passport.deserializeUser(async (id: string, done) => {
    try {
        // Retrieve the user from your userStore by the userID.
        const user = await userStore.get(id, true); // `true` indicates search by userID
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


// Routes

// Homepage and other views
app.get("/", (req: Request, res: Response) => {
    res.render("index");
});

app.get("/register", (req: Request, res: Response) => {
    res.render("register");
});

app.get("/login", (req: Request, res: Response) => {
    res.render("login");
});

// Registration Challenge Endpoint (GET)
app.get(
    "/webauthn/register",
    passport.authenticate("webauthn", { session: false }),
    (req, res) => {
        // Return challenge options without storing them in session
        res.json(req.user);
    }
);

// Registration Callback Endpoint (POST)
app.post("/webauthn/register", passport.authenticate("webauthn", { session: false }),
    (req, res) => {
    // On success, req.user will contain the updated user (with the new passkey).
    res.json({ user: req.user });
});

// Login Challenge Endpoint (GET)
app.get(
    "/webauthn/login",
    passport.authenticate("webauthn", { session: false }),
    (req, res) => {
        // Return challenge options without storing them in session
        res.json(req.user);
    }
);

// Login Callback Endpoint (POST)
app.post("/webauthn/login", passport.authenticate("webauthn"),
    (req, res) => {
    // On success, req.user will be the authenticated user.
    res.json({ user: req.user });
});

// Updated /account route: use req.user instead of req.session.userID
app.get("/account", async (req: Request, res: Response) => {
    if (!req.isAuthenticated() || !req.user) {
        return res.redirect("/login");
    }

    try {
        res.render("account", { passkeys: (req.user as any).passkeys });
    } catch (error) {
        console.error("Error loading account:", error);
        res.redirect("/login");
    }
});

app.get("/account/passkeys", async (req: Request, res: Response) => {
    if (!req.session.userID) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    try {
        const user = await User.findOne({ userID: req.session.userID }).lean();
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({ passkeys: user.passkeys });
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

// MongoDB Connection (Only for user data, not sessions)
mongoose
    .connect(process.env.MONGO_URI || "mongodb://localhost:27017/webauthnDB")
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB connection error:", err));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));