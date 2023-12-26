import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import jwt, { JsonWebTokenError } from 'jsonwebtoken';

export type AuthRequest = Request & { user?: { email?: string; uid: string } };

export const verifyJwt = asyncHandler(
    async (req: AuthRequest, res: Response, next) => {
        const authHeader = req.headers.authorization;

        if (!authHeader?.startsWith('Bearer ')) {
            res.status(401).json({ message: 'Missing auth header.' });
            return;
        }

        const secreteAt = process.env.ACCESS_TOKEN_SECRETE;
        const secreteRt = process.env.REFRESH_TOKEN_SECRETE;

        if (!secreteAt || !secreteRt) {
            res.status(500).json({ message: 'Internal server error.' });
            return;
        }

        const token = authHeader.split(' ')[1];

        jwt.verify(
            token,
            secreteAt,
            (error: JsonWebTokenError | null, decoded: any) => {
                if (error || !decoded.user) {
                    res.status(403).json({ message: 'Invalid token' });
                    return;
                }

                req.user = decoded.user;
                next();
            },
        );
    },
);
