import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import session from "express-session";
import passport from "passport";
import router from './routes/auth';

dotenv.config();

const app = express();

// View Engine Setup
app.set('views', path.join(__dirname, '../src/views'));
app.set('view engine', 'ejs');

// Middleware to parse JSON & URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 🛠️ FIX: Apply session middleware globally
app.use(
    session({
        secret: process.env.SESSION_SECRET || 'your_secret_key',
        resave: false,
        saveUninitialized: false,
        cookie: {
            secure: false, // Secure cookies in production
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000, // 1 day session expiry
        },
    })
);

// 🛠️ FIX: Initialize Passport and Sessions in Correct Order
app.use(passport.initialize());
app.use(passport.session());

// Use Routes
app.use('/', router);

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});