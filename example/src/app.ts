// src/app.ts

import express from 'express';
import session from 'express-session';
import passport from './config/passport';
import MongoStore from 'connect-mongo';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import path from 'path';
import indexRoutes from './routes/index';
import authRoutes from './routes/auth';
import accountRoutes from './routes/account';

dotenv.config();

const app = express();

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/passport-webauthn2', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
} as any)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Set EJS as templating engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Configure session middleware with MongoDB store
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret', // Use a strong secret in production
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI || 'mongodb://localhost:27017/passport-webauthn2',
        collectionName: 'sessions',
        ttl: 14 * 24 * 60 * 60, // Session expiration in seconds (14 days)
    }),
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Set to true in production
        httpOnly: true,
        maxAge: 14 * 24 * 60 * 60 * 1000, // Cookie expiration in milliseconds (14 days)
    },
}));

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/', indexRoutes);
app.use('/', authRoutes);
app.use('/account', accountRoutes);

// Error Handling Middleware
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

export default app;