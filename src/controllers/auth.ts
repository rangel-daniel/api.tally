import { Request, Response } from 'express';
import { AuthRequest } from '../middleware/verifyJwt';
import asyncHandler from 'express-async-handler';
import { AuthUser, AuthUserDoc, GuestUser, User } from '../models/User';
import { sendEmail } from '../utils/email';
import Secrete from '../models/secrete';
import bcrypt from 'bcrypt';
import jwt, { JsonWebTokenError } from 'jsonwebtoken';

export const isAuth = (req: AuthRequest) => {
    return req.user ? req.user?.email && req.user.uid : false;
};
const emailUser = async (type: 'activate' | 'password', user: AuthUserDoc) => {
    const { _id: uid, tempEmail, name } = user;
    let email = user.email;

    // True when email is changed and needs to be confirmed.
    if (type === 'activate' && tempEmail && tempEmail !== 'new') {
        email = tempEmail;
    }

    const userInfo = { uid, email, name };

    const secrete = await Secrete.create({ type, uid });

    await sendEmail(userInfo, secrete);
};

/**
 * @description
 * if _id is passed in the request body, it'll try to turn a guest user to an
 * authenticated user.
 * */
export const registerUser = asyncHandler(
    async (req: Request, res: Response) => {
        const { email, name, password, _id } = req.body;

        if (!email || !name || !password) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const info = {
            email,
            name,
            password,
        };

        if (_id) {
            const guest = await GuestUser.findByIdAndDelete(_id);
            if (!guest) {
                res.status(404).json({ message: 'User does not exist.' });
                return;
            }
        }

        const user = await AuthUser.create(_id ? { ...info, _id } : info);

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

export const changePasswordWithToken = asyncHandler(
    async (req: Request, res: Response) => {
        const { token } = req.params;
        const { password } = req.body;

        if (!password || !token) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const secrete = await Secrete.findOne({ token });
        const validUser = await User.exists({ _id: secrete?.uid });

        if (!secrete || secrete.type !== 'password' || !validUser) {
            res.status(400).json({ message: 'Invalid token.' });
            return;
        }

        const user = await AuthUser.findById(secrete.uid).select('password');

        if (!user) {
            res.status(404).json({ message: 'Invalid token.' });
            return;
        }

        user.password = password;
        await user.save();

        await secrete.deleteOne();

        res.json({ message: 'Password updated.' });
    },
);

export const updateEmail = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { email } = req.body;
        if (!req?.user?.email || !req?.user?.uid || !email) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const user = await AuthUser.findById(req.user.uid);

        if (!user) {
            res.status(404).json({ message: 'User not found.' });
            return;
        }

        if (email != user.email) {
            user.tempEmail = email;
            const updatedUser = await user.save();
            await emailUser('activate', updatedUser);

            logout(req, res, () => {});
        }

        res.json({ message: 'Email updated.' });
    },
);

export const updatePassword = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { password } = req.body;

        if (!req?.user?.email || !req?.user?.uid || !password) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const user = await AuthUser.findById(req.user.uid);

        if (!user) {
            res.status(404).json({ message: 'User not found.' });
            return;
        }

        user.password = password;

        const updatedUser = await user.save();
        await emailUser('activate', updatedUser);

        logout(req, res, () => {});
        res.json({ message: 'Password updated.' });
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

const guestLogin = async (res: Response, secrete: string) => {
    const user = await GuestUser.create({});

    const accessToken = jwt.sign(
        {
            'user': {
                'uid': user._id,
            },
        },
        secrete,
        { expiresIn: '30d' },
    );

    res.json({ accessToken });
};

/**
 * @description
 * if email and password are missing, the user will login as guest.
 * */
export const login = asyncHandler(async (req: Request, res: Response) => {
    const secreteAt = process.env.ACCESS_TOKEN_SECRETE;
    const secreteRt = process.env.REFRESH_TOKEN_SECRETE;

    if (!secreteAt || !secreteRt) {
        res.status(500).json({ message: 'Internal server error.' });
        return;
    }

    const { email, password } = req.body;

    if (!email || !password) {
        guestLogin(res, secreteAt);
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
            'user': {
                'email': user.email,
                'uid': user._id,
            },
        },
        secreteRt,
        { expiresIn: '30d' },
    );

    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
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
            const { uid } = decoded.user;

            if (error || !uid) {
                res.status(403).json({ message: 'Missing cookie.' });
                return;
            }

            const user = await AuthUser.findById(uid);

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
