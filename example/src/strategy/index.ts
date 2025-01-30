// src/strategy/index.ts
import passport from "passport";
import { SimpleWebAuthnStrategy } from "passport-simple-webauthn2";
import { Request } from "express";
import { findUserById } from "../models/user";

passport.serializeUser((user: any, done) => {
    done(null, Buffer.from(user.id).toString("base64url"));
});

passport.deserializeUser((id: string, done) => {
    const user = findUserById(Buffer.from(id, "base64url"));
    if (user) {
        done(null, user);
    } else {
        done(new Error("User not found"), null);
    }
});

const strategy = new SimpleWebAuthnStrategy({
    getUser: async (req: Request, id: Uint8Array) => {
        const user = findUserById(id);
        return user || null;
    },
});

passport.use(strategy);

export default passport;