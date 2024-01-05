import asyncHandler from 'express-async-handler';
import isMongoId from 'validator/lib/isMongoId';

import { AuthRequest } from '../middleware/verifyJwt';
import { Response } from 'express';
import { Poll } from '../models/Poll';
import { Tally } from '../models/Tally';
import { Types } from 'mongoose';

export const vote = asyncHandler(async (req: AuthRequest, res: Response) => {
    const { clientIp: ip, uid, isAuth } = req;
    const { pid, name } = req.body;
    let opts = req.body.opts;

    if (!opts || !opts.length || !isMongoId(pid) || !uid || !ip) {
        console.log(!opts, !opts.length, !isMongoId(pid), !uid, !ip);

        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const poll = await Poll.findById(pid).select('settings opts').lean();

    if (!poll) {
        res.status(404).json({ message: 'Poll not found.' });
        return;
    }

    const { settings } = poll;
    const options = poll.opts.map((opt) => opt._id.toString());

    if (settings.reqLogin && !isAuth) {
        res.status(400).json({
            message:
                'User account required. Please sign up or log in to vote.',
        });
        return;
    }

    opts = [...new Set(opts)];
    opts = opts.filter((opt: string) => options.includes(opt));

    if (!opts.length || (opts.length > 1 && !settings.allowMultiple)) {
        console.log(opts, `Allow multiple: ${settings.allowMultiple}`);
        res.status(400).json({ message: 'Invalid options.' });
        return;
    }

    if (settings.reqNames && !name) {
        res.status(400).json({ message: 'Name is required.' });
        return;
    }

    const deadline = settings.deadline
        ? new Date(settings.deadline)
        : undefined;

    if (deadline && deadline > new Date()) {
        res.status(400).json({ message: 'Expired poll.' });
        return;
    }

    const tally = await Tally.findOne({ uid, pid });

    if (tally) {
        if (!settings.allowEdit) {
            res.status(409).json({ message: 'Already voted.' });
            return;
        }

        tally.name = name;
        tally.opts = opts;
        tally.ip = ip;

        await tally.save();

        res.json({ message: 'Vote updated.' });
        return;
    }

    if (!settings.reqLogin) {
        const exists = await Tally.exists({ ip });
        if (exists) {
            res.status(409).json({
                message:
                    'Someone on your network has already participated in this poll.',
            });
            return;
        }
    }

    await Tally.create({ uid, pid, opts, name, ip });

    await Poll.findOneAndUpdate(new Types.ObjectId(pid), {
        $inc: { users: 1 },
    });

    res.json({ message: 'Vote casted.' });
});
