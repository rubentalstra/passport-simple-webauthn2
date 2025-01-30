import passport from "passport";
import { SimpleWebAuthnStrategy } from "passport-simple-webauthn2";
import { findUserById } from "./models/user";

// Serialize user for session storage
passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, done) => {
    const user = await findUserById(id);
    done(null, user || null);
});

const webAuthnStrategy = new SimpleWebAuthnStrategy({
    findPasskeyByCredentialID: async (credentialID) => {
        const user = [...users.values()].find(u =>
            u.credentials.some(c => c.id === credentialID)
        );
        return user ? user.credentials.find(c => c.id === credentialID) : null;
    },
    updatePasskeyCounter: async (credentialID, newCounter) => {
        const user = [...users.values()].find(u =>
            u.credentials.some(c => c.id === credentialID)
        );
        if (user) {
            const passkey = user.credentials.find(c => c.id === credentialID);
            if (passkey) passkey.counter = newCounter;
        }
    },
    findUserByWebAuthnID: async (webauthnUserID) => {
        return [...users.values()].find(user => user.id === webauthnUserID) || null;
    },
    registerPasskey: async (user, passkey) => {
        user.credentials.push(passkey);
    }
});

// Use the strategy with Passport
passport.use(webAuthnStrategy);

export default passport;