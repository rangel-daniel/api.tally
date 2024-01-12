import { Request, Response } from 'express';
import { AuthRequest } from '../middleware/verifyJwt';
import asyncHandler from 'express-async-handler';
import { AuthUser, AuthUserDoc, GuestUser, User } from '../models/User';
import { sendEmail } from '../utils/email';
import Secrete from '../models/secrete';
import bcrypt from 'bcrypt';
import jwt, { JsonWebTokenError } from 'jsonwebtoken';

const emailUser = async (type: 'activate' | 'password', user: AuthUserDoc) => {
    const { _id: uid, tempEmail, name } = user;
    let email = user.email;

    if (type === 'activate') {
        if (!tempEmail) return;
        if (tempEmail !== 'new') email = tempEmail;
    }

    const userInfo = { uid, email, name };

    const secrete = await Secrete.create({ type, uid });

    await sendEmail(userInfo, secrete);
};

export const resendEmail = asyncHandler(async (req: Request, res: Response) => {
    const { email } = req.body;
    const type: 'activate' | 'password' = req.body.type;

    if (!email || !type) {
        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const user = await AuthUser.findOne({ email });

    if (!user) {
        res.status(404).json({ message: 'Email not found.' });
        return;
    }

    emailUser(type, user);
    res.json({ message: 'Email sent.' });
});

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

        const duplicate = await AuthUser.exists({ email });

        if (duplicate) {
            res.status(409).json({ message: 'Duplicate email.' });
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

const guestLogin = async (res: Response, secrete: string) => {
    const user = await GuestUser.create({});

    const accessToken = jwt.sign(
        {
            'isAuth': false,
            'uid': user._id,
        },
        secrete,
        { expiresIn: '30d' },
    );

    res.json({ accessToken });
};

/**
 * @description
 * If email and password are missing, the user will login as guest.
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
            'isAuth': true,
            'uid': user._id,
        },
        secreteAt,
        { expiresIn: '30m' },
    );

    const refreshToken = jwt.sign(
        {
            'isAuth': true,
            'uid': user._id,
        },
        secreteRt,
        { expiresIn: '30d' },
    );

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
    });

    res.json({ accessToken });
});

/**
 * @description
 * Used for initial account activation and to confirm new email.
 * */
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
            const duplicate = await AuthUser.exists({ email: user.tempEmail });

            if (duplicate) {
                res.status(409).json({ message: 'Duplicate email.' });
                return;
            }

            user.email = user.tempEmail;
        }

        user['tempEmail'] = undefined;
        await Secrete.deleteOne({ _id: secrete._id });
        await user.save();

        res.json({ message: 'Account successfully activated!' });
    },
);

export const forgotPassword = asyncHandler(
    async (req: Request, res: Response) => {
        const { email } = req.body;

        const user = await AuthUser.findOne({ email });

        if (!user) {
            res.status(404).json({ message: 'User does not exist.' });
            return;
        }

        await emailUser('password', user);

        res.json({ message: 'Email sent.' });
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
        const { isAuth, uid } = req;

        if (!isAuth || !uid || !email) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const duplicate = await AuthUser.exists({ email });

        if (duplicate) {
            res.status(409).json({ message: 'Duplicate email.' });
            return;
        }

        const user = await AuthUser.findById(uid);

        if (!user) {
            res.status(404).json({ message: 'User not found.' });
            return;
        }

        if (email.trim() != user.email) {
            user.tempEmail = email;
            const updatedUser = await user.save();
            await emailUser('activate', updatedUser);
        }

        res.json({ message: 'Email updated.' });
    },
);

export const updatePassword = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { current, update } = req.body;
        const { isAuth, uid } = req;

        if (!isAuth || !uid || !update || !current) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const user = await AuthUser.findById(uid);

        if (!user) {
            res.status(404).json({ message: 'User not found.' });
            return;
        }

        const match = await bcrypt.compare(current, user.password);

        if (!match) {
            res.status(401).json({ message: 'Invalid password.' });
            return;
        }

        user.password = update;

        await user.save();
        res.json({ message: 'Password updated.' });
    },
);

export const updateName = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { name } = req.body;
        const { isAuth, uid } = req;

        if (!isAuth || !uid || !name) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const user = await AuthUser.findById(uid);

        user.name = name;
        await user.save();

        res.json({ message: 'Name updated.' });
    },
);

export const refresh = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        res.status(401).json({ message: 'Missing token.' });
        return;
    }

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
            const { uid, isAuth } = decoded;

            if (error || !uid) {
                res.status(403).json({ message: 'Missing cookie.' });
                return;
            }

            const exists = await AuthUser.exists({ _id: uid });

            if (!exists) {
                res.status(404).json({ message: 'User not found' });
                return;
            }

            const accessToken = jwt.sign(
                {
                    'isAuth': isAuth,
                    'uid': uid,
                },
                secreteAt,
                { expiresIn: '30m' },
            );

            res.json({ accessToken });
        },
    );
});

export const logout = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        res.status(204);
        return;
    }

    res.clearCookie('refreshToken', {
        httpOnly: true,
        sameSite: 'none',
        secure: true,
    });

    res.json({ message: 'Logged out!' });
});

export const deleteAccount = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { password } = req.body;
        const { isAuth, uid } = req;

        if (!isAuth || !uid || !password) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const user = await AuthUser.findById(uid);

        if (!user) {
            res.status(404).json({ message: 'User not found.' });
            return;
        }

        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            res.status(401).json({ message: 'Invalid password.' });
            return;
        }

        const { deletedCount } = await user.deleteOne();

        if (!deletedCount) {
            res.status(500).json({ message: 'Internal server error.' });
            return;
        }

        logout(req, res, () => {});
    },
);
