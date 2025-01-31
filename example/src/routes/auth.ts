import express from "express";
import passport from "passport";
import { SimpleWebAuthnStrategy } from "../strategy/SimpleWebAuthnStrategy";
import type { Passkey } from "../types";

const router = express.Router();

// Mock database
const users: { [key: string]: { userID: string; passkeys: Passkey[] } } = {};

// Setup WebAuthn strategy
passport.use(
    new SimpleWebAuthnStrategy({
        findPasskeyByCredentialID: async (credentialID) => {
            for (const user of Object.values(users)) {
                const passkey = user.passkeys.find((p) => p.id === credentialID);
                if (passkey) return passkey;
            }
            return null;
        },
        updatePasskeyCounter: async (credentialID, newCounter) => {
            for (const user of Object.values(users)) {
                const passkey = user.passkeys.find((p) => p.id === credentialID);
                if (passkey) passkey.counter = newCounter;
            }
        },
        registerPasskey: async (userID, passkey) => {
            if (!users[userID]) {
                users[userID] = { userID, passkeys: [] };
            }
            users[userID].passkeys.push(passkey);
        },
    })
);

passport.serializeUser((user: any, done) => {
    done(null, user.userID);
});

passport.deserializeUser((userID: string, done) => {
    done(null, users[userID] || null);
});

// 🔹 Register Page
router.get("/register", (req, res) => {
    res.render("register");
});

// 🔹 Handle Registration
router.post("/register", async (req, res, next) => {
    req.body.path = "/register-callback";
    passport.authenticate("simple-webauthn", (err, user) => {
        if (err) return next(err);
        if (!user) return res.redirect("/register?error=failed");
        req.login(user, () => res.redirect("/account"));
    })(req, res, next);
});

// 🔹 Login Page
router.get("/login", (req, res) => {
    res.render("login");
});

// 🔹 Handle Login
router.post("/login", async (req, res, next) => {
    req.body.path = "/login-callback";
    passport.authenticate("simple-webauthn", (err, user) => {
        if (err) return next(err);
        if (!user) return res.redirect("/login?error=failed");
        req.login(user, () => res.redirect("/account"));
    })(req, res, next);
});

// 🔹 Account Page (Show Passkeys)
router.get("/account", (req, res) => {
    if (!req.isAuthenticated()) return res.redirect("/login");
    const user = users[req.user as string];
    res.render("account", { user });
});

// 🔹 Logout
router.get("/logout", (req, res) => {
    req.logout(() => {
        res.redirect("/");
    });
});

export default router;