import { Request, Response } from 'express';
import { AuthRequest, DecodedAt } from '../middleware/verifyJwt';
import asyncHandler from 'express-async-handler';
import { AuthUser, AuthUserDoc, GuestUser, GuestUserDoc } from '../models/User';
import { sendEmail } from '../utils/email';
import Secrete from '../models/secrete';
import bcrypt from 'bcrypt';
import jwt, { JsonWebTokenError } from 'jsonwebtoken';

export const signup = asyncHandler(async (req: Request, res: Response) => {
    const { email, name, password } = req.body;

    if (!email || !name || !password) {
        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const duplicate = await AuthUser.exists({ email });

    if (duplicate) {
        res.status(409).json({ message: 'Duplicate email.' });
        return;
    }

    const user = await AuthUser.create({ email, name, password });

    await emailUser(false, user);

    const success = await setRefreshToken(res, user);

    if (success) res.json({ message: 'Successful sign up!' });
});

/**
 * @description
 * If email and password are missing, the user will login as guest.
 * */
export const signin = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;

    // Guest login
    if (!email || !password) {
        const user = await GuestUser.create({});
        const success = await setRefreshToken(res, user);
        if (success) res.json({ message: 'Signed in as guest!' });
        return;
    }

    const user = await AuthUser.findOne({ email });

    if (!user) {
        res.status(404).json({ message: 'User not found.' });
        return;
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        res.status(401).json({ message: 'Invalid password.' });
        return;
    }

    const success = await setRefreshToken(res, user);
    if (success) res.json({ message: 'Successful sign up!' });
});

export const authenticate = asyncHandler(async (req: AuthRequest, res: Response) => {
    const { uid, isAuth } = req;
    const { email, name, password } = req.body;

    if (isAuth) {
        res.status(400).json({ message: 'User usalready authenticated.' });
        return;
    }

    const duplicate = await AuthUser.exists({ email });
    if (duplicate) {
        res.status(409).json({ message: 'Duplicate email.' });
        return;
    }

    const guestUser = await GuestUser.findById(uid);
    if (!guestUser) {
        res.status(404).json({ message: 'User does not exist.' });
        return;
    }

    const authUser = await AuthUser.create({
        _id: uid,
        email,
        name,
        password,
    });
    await guestUser.remove();

    const success = await setRefreshToken(res, authUser);

    if (success) res.json({ message: 'Successful sign up!' });
});

export const emailUser = async (isPassword: boolean, user: AuthUserDoc) => {
    const { _id: uid, tempEmail, name } = user;
    let email = user.email;

    if (!isPassword && tempEmail) {
        email = tempEmail;
    }

    const userInfo = { uid, email, name };

    const secrete = await Secrete.create({ isPassword, uid });

    await sendEmail(userInfo, secrete);
};

export const resendEmail = asyncHandler(async (req: Request, res: Response) => {
    const { email, isPassword } = req.body;

    if (!email || isPassword !== undefined) {
        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const user = await AuthUser.findOne({ email });

    if (!user) {
        res.status(404).json({ message: 'Email not found.' });
        return;
    }

    emailUser(isPassword, user);
    res.json({ message: 'Email sent.' });
});

const setRefreshToken = (res: Response, user: AuthUserDoc | GuestUserDoc) => {
    const isAuth = 'email' in user;
    const secreteRt = process.env.REFRESH_TOKEN_SECRETE;

    if (!secreteRt) {
        res.status(500).json({ message: 'Failed to retrieve environment variables.' });
        return Promise.resolve(null);
    }

    const refreshToken = jwt.sign(
        {
            'isAuth': isAuth,
            'uid': user._id.toString(),
        },
        secreteRt,
        { expiresIn: '30d' },
    );

    const oneMonth = 30 * 24 * 60 * 60 * 1000;

    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: oneMonth,
    });

    return isAuth
        ? AuthUser.findByIdAndUpdate(user._id, { token: refreshToken })
        : GuestUser.findByIdAndUpdate(user._id, { token: refreshToken });
};

/**
 * @description
 * Used for initial account activation and to confirm new email.
 * */
export const activateAccount = asyncHandler(async (req: Request, res: Response) => {
    const { token } = req.body;

    const secrete = await Secrete.findOne({ token }).lean();

    if (!secrete || secrete.isPassword) {
        res.status(404).json({ message: 'Invalid token.' });
        return;
    }

    const user = await AuthUser.findById(secrete.uid);

    if (!user || (!user.tempEmail && user.isVerified)) {
        res.status(404).json({ message: 'Invalid token.' });
        return;
    }

    if (user.isVerified) {
        const duplicate = await AuthUser.exists({ email: user.tempEmail });

        if (duplicate) {
            res.status(409).json({ message: 'Duplicate email.' });
            return;
        }

        user.email = user.tempEmail;
        user.tempEmail = undefined;
    } else {
        user.isVerified = true;
    }

    await Secrete.deleteOne({ _id: secrete._id });
    await user.save();

    res.json({ message: 'Account successfully activated!' });
});

export const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
    const { email } = req.body;

    const user = await AuthUser.findOne({ email });

    if (!user) {
        res.status(404).json({ message: 'User does not exist.' });
        return;
    }

    await emailUser(true, user);

    res.json({ message: 'Email sent.' });
});

export const changePasswordWithToken = asyncHandler(
    async (req: Request, res: Response) => {
        const { token } = req.params;
        const { password } = req.body;

        if (!password || !token) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const secrete = await Secrete.findOne({ token });

        if (!secrete || !secrete.isPassword) {
            res.status(400).json({ message: 'Invalid token.' });
            return;
        }

        const user = await AuthUser.findById(secrete.uid).select('password');

        if (!user) {
            res.status(404).json({ message: 'User does not exist.' });
            return;
        }

        user.password = password;

        await user.save();

        await secrete.deleteOne();

        res.json({ message: 'Password updated.' });
    },
);

export const refresh = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
        res.status(400).json({ message: 'Missing token.' });
        return;
    }

    const secreteRt = process.env.REFRESH_TOKEN_SECRETE;

    if (!secreteRt) {
        res.status(500).json({ message: 'Internal server error.' });
        return;
    }

    jwt.verify(
        refreshToken,
        secreteRt,
        async (error: JsonWebTokenError | null, decoded: any) => {
            if (error) {
                res.status(401).json({ message: 'Token is invalid or has expired.' });
                return;
            }

            const secreteAt = process.env.ACCESS_TOKEN_SECRETE;

            if (!secreteAt) {
                res.status(500).json({ message: 'Internal server error.' });
                return;
            }

            const { uid, isAuth } = decoded;

            const user: AuthUserDoc | GuestUserDoc | null = isAuth
                ? await AuthUser.findOne({ _id: uid, token: refreshToken }).lean()
                : await GuestUser.findOne({ _id: uid, token: refreshToken }).lean();

            if (!user) {
                res.status(401).json({ message: 'Token is invalid or has expired.' });
                return;
            }

            const jwtFields: DecodedAt = { 'isAuth': isAuth, 'uid': uid };
            const isVerified: boolean | undefined =
                'isVerified' in user ? user.isVerified : undefined;

            if (isVerified !== undefined) {
                jwtFields['isVerified'] = isVerified;
            }

            const accessToken = jwt.sign(jwtFields, secreteAt, { expiresIn: '30m' });

            res.json({ accessToken });
        },
    );
});

export const signout = asyncHandler(async (req: Request, res: Response) => {
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

export const deleteAccount = asyncHandler(async (req: AuthRequest, res: Response) => {
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

    signout(req, res, () => {});
});
