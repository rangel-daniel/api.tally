import asyncHandler from 'express-async-handler';
import bcrypt from 'bcrypt';
import { AuthRequest } from '../middleware/verifyJwt';
import { Response } from 'express';
import { AuthUser } from '../models/User';
import { emailUser } from './auth';

export const getUser = asyncHandler(async (req: AuthRequest, res: Response) => {
    const { isAuth, uid } = req;

    if (!uid || !isAuth) {
        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const user = await AuthUser.findById(uid).lean();

    if (!user) {
        res.status(404).json({ message: 'User not found.' });
        return;
    }

    res.json({
        user: {
            name: user.name,
            email: user.email,
            tempEmail: user.tempEmail,
        },
    });
});

export const updateName = asyncHandler(async (req: AuthRequest, res: Response) => {
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
});

export const updateEmail = asyncHandler(async (req: AuthRequest, res: Response) => {
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
        await emailUser(false, updatedUser);
    }

    res.json({ message: 'Email updated.' });
});

export const updatePassword = asyncHandler(async (req: AuthRequest, res: Response) => {
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
});
