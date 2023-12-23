import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { AuthUser, AuthUserDoc, User } from '../models/User';
import { sendEmail } from '../utils/email';
import Secrete from '../models/secrete';
import path from 'path';
import bcrypt from 'bcrypt';
import jwt, { JsonWebTokenError } from 'jsonwebtoken';

const emailUser = async (type: 'activate' | 'password', user: AuthUserDoc) => {
    const { _id: uid, email, name } = user;
    const userInfo = { uid, email, name };

    const secrete = await Secrete.create({ type, uid });

    await sendEmail(userInfo, secrete);
};

export const registerUser = asyncHandler(
    async (req: Request, res: Response) => {
        const { email: _email, name: _name, password } = req.body;
        const user = await AuthUser.create({
            email: _email,
            name: _name,
            password,
            secrete: { type: 'activate' },
        });

        await emailUser('activate', user);

        res.json({ message: 'Successful registration!' });
    },
);

export const activateAccount = asyncHandler(
    async (req: Request, res: Response) => {
        const { token } = req.params;

        const secrete = await Secrete.findOne({ token }).lean();

        if (!secrete || secrete.type !== 'activate') {
            res.status(404).json({ message: 'Invalid token.' });
            return;
        }

        const user = await AuthUser.findById(secrete.uid).select(
            'email tempEmail',
        );

        if (!user || !user.tempEmail) {
            res.status(404).json({ message: 'Invalid token.' });
            return;
        }

        if (user.tempEmail !== 'new') {
            user.email = user.tempEmail;
        }

        user['tempEmail'] = undefined;
        await Secrete.deleteOne({ _id: secrete._id });
        await user.save();

        res.json({ message: 'Account successfully activated!' });
    },
);

export const changePassword = asyncHandler(
    async (req: Request, res: Response) => {
        const { method } = req;
        const { token } = req.params;

        const secrete = await Secrete.findOne({ token }).lean();
        const validUser = await User.exists({ _id: secrete?.uid });

        if (!secrete || secrete.type !== 'password' || !validUser) {
            res.status(404).json({ message: 'Invalid token.' });
            return;
        }

        if (method === 'GET') {
            res.sendFile(
                path.join(
                    __dirname,
                    '..',
                    '..',
                    'templates',
                    'changePassword.html',
                ),
            );
            return;
        }

        const { password } = req.body;

        const user = await AuthUser.findById(secrete.uid).select('password');

        if (!user) {
            res.status(404).json({ message: 'Invalid token.' });
            return;
        }

        user.password = password;
        await user.save();

        await Secrete.deleteOne({ _id: secrete._id });

        res.json({ message: 'Password updaed.' });
    },
);

export const forgotPassword = asyncHandler(
    async (req: Request, res: Response) => {
        const { email } = req.body;

        const user = await AuthUser.findOne({ email });

        if (!user) {
            res.status(400).json({ message: 'User does not exist.' });
            return;
        }

        await emailUser('password', user);

        res.json({ message: 'Email sent.' });
    },
);

export const login = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
        res.status(400).json({ message: 'All fields are required.' });
        return;
    }

    const user = await AuthUser.findOne({ email }).lean();

    if (!user) {
        res.status(401).json({ message: 'User not found.' });
        return;
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        res.status(401).json({ message: 'Invalid password.' });
        return;
    }

    const secreteAt = process.env.ACCESS_TOKEN_SECRETE;
    const secreteRt = process.env.REFRESH_TOKEN_SECRETE;

    if (!secreteAt || !secreteRt) {
        res.status(500).json({ message: 'Internal server error.' });
        return;
    }

    const accessToken = jwt.sign(
        {
            'user': {
                'email': user.email,
                'uid': user._id,
            },
        },
        secreteAt,
        { expiresIn: '30m' },
    );

    const refreshToken = jwt.sign(
        {
            'email': user.email,
        },
        secreteRt,
        { expiresIn: '30d' },
    );

    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 30 * 24 * 60 * 60 * 1000,
    });

    res.json({ accessToken });
});

export const refresh = asyncHandler(async (req: Request, res: Response) => {
    const cookies = req.cookies;

    if (!cookies?.jwt) {
        res.status(401).json({ message: 'Missing cookie.' });
        return;
    }

    const refreshToken = cookies.jwt;

    const secreteAt = process.env.ACCESS_TOKEN_SECRETE;
    const secreteRt = process.env.REFRESH_TOKEN_SECRETE;

    if (!secreteAt || !secreteRt) {
        res.status(500).json({ message: 'Internal server error.' });
        return;
    }

    jwt.verify(
        refreshToken,
        secreteRt,
        async (error: JsonWebTokenError | null, decoded: any) => {
            if (error) {
                res.status(403).json({ message: 'Missing cookie.' });
                return;
            }
            const user = AuthUser.findById(decoded.uid);
            const accessToken = jwt.sign(
                {
                    'user': {
                        'email': user.email,
                        'uid': user._id,
                    },
                },
                secreteAt,
                { expiresIn: '30m' },
            );

            res.json({ accessToken });
        },
    );
});

export const logout = asyncHandler(async (req: Request, res: Response) => {
    const { jwt: refreshToken } = req.cookies;
    if (!refreshToken) {
        res.status(204);
        return;
    }

    res.clearCookie('jwt', { httpOnly: true, sameSite: 'none', secure: true });
    res.json({ message: 'Logged out!' });
});
