import passport from "passport";
import { SimpleWebAuthnStrategy } from "passport-simple-webauthn2";
import {findUserById, getAllUsers, updateUser} from "./models/user"; // Ensure updateUser is implemented

// Serialize user for session storage
passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, done) => {
    try {
        const user = await findUserById(id);
        done(null, user || null);
    } catch (error) {
        done(error, null);
    }
});

const webAuthnStrategy = new SimpleWebAuthnStrategy({
    findPasskeyByCredentialID: async (credentialID) => {
        try {
            const users = await getAllUsers(); // Ensure this function fetches all users
            for (const user of users) {
                const passkey = user.credentials.find((c: { id: string }) => c.id === credentialID);
                if (passkey) return passkey;
            }
            return null;
        } catch (error) {
            console.error("Error finding passkey by credential ID:", error);
            return null;
        }
    },
    updatePasskeyCounter: async (credentialID, newCounter) => {
        try {
            const users = await getAllUsers();
            for (const user of users) {
                const passkey = user.credentials.find((c: { id: string }) => c.id === credentialID);
                if (passkey) {
                    passkey.counter = newCounter;
                    await updateUser(user.id, { credentials: user.credentials }); // Persist changes
                    return;
                }
            }
        } catch (error) {
            console.error("Error updating passkey counter:", error);
        }
    },
    findUserByWebAuthnID: async (webauthnUserID) => {
        try {
            return await findUserById(webauthnUserID) || null;
        } catch (error) {
            console.error("Error finding user by WebAuthn ID:", error);
            return null;
        }
    },
    registerPasskey: async (user, passkey) => {
        try {
            user.credentials.push(passkey);
            await updateUser(user.id, { credentials: user.credentials }); // Persist passkey
        } catch (error) {
            console.error("Error registering passkey:", error);
        }
    }
});

// Use the strategy with Passport
passport.use(webAuthnStrategy);

export default passport;