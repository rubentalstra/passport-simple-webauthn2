// src/routes/account.ts

import express, { Request, Response } from 'express';
import { ensureAuthenticated } from '../middleware/authMiddleware';

const router = express.Router();

// Account Page Route
router.get('/', ensureAuthenticated, (req: Request, res: Response) => {
    const user = req.user as any;
    res.render('account', { user });
});

export default router;