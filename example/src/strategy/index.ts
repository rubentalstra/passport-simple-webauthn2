import passport from "passport";
import { SimpleWebAuthnStrategy } from "passport-simple-webauthn2";
import { Request } from "express";
import { findUserById } from "../../../src/services/userService";

passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id: string, done) => {
    try {
        const user = await findUserById(id);
        if (user) {
            done(null, user);
        } else {
            done(new Error("User not found"), null);
        }
    } catch (error) {
        done(error, null);
    }
});

const strategy = new SimpleWebAuthnStrategy({
    getUser: async (req: Request, id: string) => {
        return await findUserById(id);
    },
});

passport.use(strategy);

export default passport;