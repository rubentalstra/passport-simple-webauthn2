// src/routes/index.ts

import express, { Request, Response } from 'express';

const router = express.Router();

// Home Page Route
router.get('/', (req: Request, res: Response) => {
    res.render('index', { user: req.user });
});

export default router;