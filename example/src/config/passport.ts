// src/config/passport.ts

import passport from 'passport';
import { SimpleWebAuthnStrategy as WebAuthnStrategy } from 'passport-simple-webauthn2';
import User, { UserModel, UserPasskey } from '../models/User';

// Initialize WebAuthn Strategy
passport.use(new WebAuthnStrategy({
    rpName: process.env.WEBAUTHN_RP_NAME || 'Example RP',
    rpID: process.env.WEBAUTHN_RP_ID || 'localhost',
    origin: process.env.WEBAUTHN_ORIGIN || 'http://localhost:3000',

    // Method to find a passkey by its credential ID
    // @ts-ignore
    findPasskeyByCredentialID: async (credentialID: string): Promise<UserPasskey | null> => {
        // Find the user who owns this passkey
        const user = await User.findOne({ 'passkeys.id': credentialID });
        if (!user) {
            return null;
        }

        // Locate the specific passkey within the user's passkeys array
        const passkey = user.passkeys.find(pk => pk.id === credentialID);
        return passkey || null;
    },

    // Method to find a user by their WebAuthn user ID
    findUserByWebAuthnID: async (webauthnUserID: string): Promise<UserModel | null> => {
        const user = await User.findById(webauthnUserID);
        return user || null;
    },

    // Method to register a new passkey for a user
    registerPasskey: async (user: UserModel, passkey: UserPasskey): Promise<void> => {
        user.passkeys.push(passkey);
        await user.save();
    },

    // Method to update the counter of an existing passkey
    updatePasskeyCounter: async (credentialID: string, newCounter: number): Promise<void> => {
        const user = await User.findOne({ 'passkeys.id': credentialID });
        if (!user) {
            throw new Error('User not found for the given credential ID');
        }

        const passkey = user.passkeys.find(pk => pk.id === credentialID);
        if (!passkey) {
            throw new Error('Passkey not found');
        }

        passkey.counter = newCounter;
        await user.save();
    },
}));

// Serialize user into the session
passport.serializeUser((user: any, done) => {
    done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

export default passport;