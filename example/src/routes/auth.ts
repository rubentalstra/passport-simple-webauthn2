// src/routes/auth.ts

import express, { Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { verifyRegistration, verifyAuthentication } from '../strategy/verifyWebAuthn';

const router = express.Router();

// Registration Page Route
router.get('/register', (req: Request, res: Response) => {
    res.render('register');
});

// Registration Response Route
// @ts-ignore
router.post('/register', async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { response, username } = req.body;

        if (!response || !username) {
            return res.status(400).json({ error: 'Missing response or username' });
        }

        const user = await verifyRegistration(req);

        req.login(user, err => {
            if (err) return next(err);
            res.redirect('/account');
        });
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

// Login Page Route
router.get('/login', (req: Request, res: Response) => {
    res.render('login');
});

// Login Response Route
// @ts-ignore
router.post('/login', async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { response, username } = req.body;

        if (!response || !username) {
            return res.status(400).json({ error: 'Missing response or username' });
        }

        const user = await verifyAuthentication(req);

        req.login(user, err => {
            if (err) return next(err);
            res.redirect('/account');
        });
    } catch (err: any) {
        res.status(400).json({ error: err.message });
    }
});

// Logout Route
router.post('/logout', (req: Request, res: Response) => {
    req.logout(err => {
        if (err) { return res.status(500).send({ error: err.message }); }
        res.redirect('/');
    });
});

export default router;