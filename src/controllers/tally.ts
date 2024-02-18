import asyncHandler from 'express-async-handler';

import { AuthRequest } from '../middleware/verifyJwt';
import { Response } from 'express';
import { Poll, PollDocument } from '../models/Poll';
import { Tally } from '../models/Tally';
import { isIP } from 'net';

/**
 * Validates vote.
 * @returns (string) validation error message.
 * @returns (undefined) Valid vote.
 * */
const isValidVote = (
    poll: PollDocument,
    opts: string[],
    name: string | undefined,
    isAuth: boolean,
): string | undefined => {
    let message!: string;

    const { settings, opts: validOpts } = poll;

    const deadline = settings.deadline ? new Date(settings.deadline) : undefined;
    const validIds = validOpts.map((opt) => opt._id.toString());

    for (let i = opts.length - 1; i >= 0; i--) {
        if (!validIds.includes(opts[i])) {
            opts.splice(i, 1);
        }
    }

    if (settings.reqSignin && !isAuth) {
        message = 'User account required. Please sign up or login to vote.';
    } else if (!opts.length || (opts.length > 1 && !settings.allowMultiple)) {
        message = 'Invalid options.';
    } else if (settings.reqNames && !name) {
        message = 'Name is required.';
    } else if (deadline && deadline > new Date()) {
        message = 'This poll has expired.';
    }

    return message;
};

export const vote = asyncHandler(async (req: AuthRequest, res: Response) => {
    const { clientIp: ip, uid, isAuth } = req;

    if (!ip || !isIP(ip) || !uid || isAuth === undefined) {
        res.status(401).json({ message: 'Unauthorized.' });
        return;
    }

    const { pid, name } = req.body;

    let duplicate = await Tally.exists({ uid, pid });

    if (duplicate) {
        res.status(409).json({ message: 'You have already participated in this poll.' });
        return;
    }

    const opts: string[] = [...new Set<string>(req.body.opts)];

    if (!opts.length || !pid) {
        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const poll = await Poll.findById(pid);
    if (!poll) {
        res.status(404).json({ message: 'Poll not found.' });
        return;
    }

    if (!poll.settings.reqSignin) {
        duplicate = await Tally.exists({ pid, ip });
        if (duplicate) {
            res.status(409).json({
                message: 'Someone on your network has already voted on this poll.',
            });
        }
    }

    const message = isValidVote(poll, opts, name, isAuth);

    if (message) {
        res.status(401).json({ message });
        return;
    }

    await Tally.create({ uid, pid, opts, name, ip });
    res.json({ message: 'Vote casted.' });

    await Poll.updateOne({ _id: pid }, { $inc: { count: 1 } });
});
