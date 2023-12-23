import { Request, Response } from 'express';
import rateLimit from 'express-rate-limit';

export const loginLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5,
    message: {
        message: 'Too many attempts to login. Reattempt in 1 minute.',
    },
    handler: (req: Request, res: Response, next, options) => {
        res.status(options.statusCode).send(options.message);
        next();
    },
    standardHeaders: true,
    legacyHeaders: true,
});
