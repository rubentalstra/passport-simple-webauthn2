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

const app = express();
const PORT = process.env.PORT || 5000;

// Set EJS as the view engine
app.set("view engine", "ejs");
app.set('views', path.join(__dirname, '../src/views'));

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "default_secret",
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false,
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000, // 1 day session expiry
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

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

// Account Page
app.get("/account", async (req, res) => {
    if (!req.session.userID) {
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

// Logout Route
app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

// MongoDB Connection
mongoose
    .connect(process.env.MONGO_URI || "mongodb://localhost:27017/webauthnDB")
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error("MongoDB connection error:", err));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));