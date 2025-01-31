// src/config/passport.ts

import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import User, { UserModel } from '../models/User';

passport.use(new LocalStrategy(
    async (username, password, done) => {
        try {
            // For simplicity, we're not using passwords. WebAuthn handles authentication.
            const user = await User.findOne({ username });
            if (!user) {
                return done(null, false, { message: 'Incorrect username.' });
            }
            // Password verification would go here if implemented
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// Serialize user into the session
passport.serializeUser((user: UserModel, done) => {
    done(null, user.id);
});

// Deserialize user from the session
passport.deserializeUser(async (id: string, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

export default passport;