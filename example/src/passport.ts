import passport from "passport";
import { SimpleWebAuthnStrategy } from "passport-simple-webauthn2";
import { findUserById } from "./models/user";

// Serialize user for session storage
passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser((id: string, done) => {
    const user = findUserById(id);
    done(null, user || null);
});

const webAuthnStrategy = new SimpleWebAuthnStrategy();

// Use the strategy with Passport
passport.use(webAuthnStrategy);

export default passport;
