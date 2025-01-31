import dotenv from "dotenv";
dotenv.config();

import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import session from "express-session";
import passport from "passport";
import path from "path";
import { User } from "./models/User"; // Import User model
import authRoutes from "./routes/authRoutes";
import accountRoutes from "./routes/accountRoutes";
import { MongoUserStore } from "./stores/MongoUserStore";

const app = express();
const PORT = process.env.PORT || 5000;

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "../src/views"));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ✅ Use cookie-based session storage (No MongoDB)
app.use(
    session({
        secret: process.env.SESSION_SECRET || "default_secret",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false, // Change to `true` if using HTTPS
            httpOnly: false, // Prevent JavaScript access
            sameSite: "lax", // Helps prevent CSRF attacks
            maxAge: 24 * 60 * 60 * 1000, // 1 day session expiry
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

const userStore = new MongoUserStore();

// ✅ Serialize and deserialize users properly
passport.serializeUser((user: any, done) => done(null, user.userID));
passport.deserializeUser(async (id: unknown, done) => {
    try {
        const user = await userStore.get(id as string, true);
        done(null, user || null);
    } catch (error) {
        done(error, null);
    }
});

// Routes
app.use("/auth", authRoutes);
app.use("/account", accountRoutes);

// Homepage
app.get("/", (req, res) => {
    res.render("index");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/login", (req, res) => {
    res.render("login");
});

// ✅ Ensure authenticated session for account page
app.get("/account", async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
        return res.redirect("/login");
    }

    try {
        const user = await User.findOne({ userID: req.session.userID }).lean();
        if (!user) {
            return res.redirect("/login");
        }
        res.render("account", { passkeys: user.passkeys });
    } catch (error) {
        console.error("Error loading account:", error);
        res.redirect("/login");
    }
});

// ✅ Logout Route
app.post("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.session.destroy(() => {
            res.redirect("/");
        });
    });
});

// ✅ MongoDB Connection (Only for user data, not sessions)
mongoose
    .connect(process.env.MONGO_URI || "mongodb://localhost:27017/webauthnDB")
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB connection error:", err));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));