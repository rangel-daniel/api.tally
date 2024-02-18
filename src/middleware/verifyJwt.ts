import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import jwt, { JsonWebTokenError } from 'jsonwebtoken';

export type AuthRequest = Request & {
    isAuth?: boolean;
    uid?: string;
    isVerified?: boolean;
};
export type DecodedAt = {
    'uid': string;
    'isAuth': boolean;
    'isVerified'?: boolean;
};

export const verifyJwt = asyncHandler(async (req: AuthRequest, res: Response, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith('Bearer ')) {
        res.status(401).json({ message: 'Missing auth header.' });
        return;
    }

    const secreteAt = process.env.ACCESS_TOKEN_SECRETE;

    if (!secreteAt) {
        res.status(500).json({ message: 'Failed to retrieve environment variables.' });
        return;
    }

    const token = authHeader.split(' ')[1];

    jwt.verify(token, secreteAt, (error: JsonWebTokenError | null, decoded: any) => {
        const decodedAt = decoded as DecodedAt;
        if (error) {
            res.status(401).json({ message: 'Token is invalid or has expired.' });
            return;
        }

        const { isAuth, uid } = decodedAt;

        if ('isVerified' in decodedAt) {
            req.isVerified = decodedAt.isVerified;
        }

        req.isAuth = isAuth;
        req.uid = uid;

        next();
    });
});
