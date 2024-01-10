import asyncHandler from 'express-async-handler';
import isMongoId from 'validator/lib/isMongoId';

import { AuthRequest } from '../middleware/verifyJwt';
import { Response } from 'express';
import { Poll, PollDocument } from '../models/Poll';
import { Tally } from '../models/Tally';
import { Server } from 'socket.io';

/**
 * Fetches and emits updated tally to connected clients via websockets.
 *
 * @param {Server} io - socket.io server instance.
 * @param {PollDocument} poll - Poll data.
 */
const emitUpdate = async (io: Server, poll: PollDocument) => {
    const pid = poll._id;
    const reqNames = poll.settings.reqNames;

    const data = await Tally.find({ pid })
        .select('updatedAt opts' + reqNames ? ' name' : '')
        .lean();

    if (data) io.to(pid).emit('update', data);
};

/**
 * Validates vote.
 * @returns (string) validation error message.
 * @returns (undefined) Valid vote.
 * */
const isValidVote = async (
    poll: PollDocument,
    opts: string[],
    name: string | undefined,
    isAuth: boolean,
): Promise<string | undefined> => {
    let message!: string;

    const { settings } = poll;
    const options = poll.opts.map((opt) => opt._id.toString());
    const deadline = settings.deadline
        ? new Date(settings.deadline)
        : undefined;

    if (opts.length > 1) opts = [...new Set(opts)];
    opts = opts.filter((opt: string) => options.includes(opt));

    if (settings.reqLogin && !isAuth) {
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

/**
 * Tries to update user's vote.
 * @returns (false) Update attempt was made but invalid.
 * @returns (true) Successful update.
 * @returns (undefined) New vote, no need to update.
 * */
const tryUpdate = async (
    poll: PollDocument,
    opts: any,
    uid: string,
    name: string,
    ip: string,
): Promise<boolean | undefined> => {
    let success!: boolean;
    const { settings } = poll;
    const tally = await Tally.findOne({ uid, pid: poll._id });

    if (tally) {
        if (settings.allowEdit) {
            tally.name = name;
            tally.opts = opts;
            tally.ip = ip;

            await tally.save();
            success = true;
        } else {
            success = false;
        }
    }

    return success;
};

const isValidIp = async (poll: PollDocument, ip: string): Promise<boolean> => {
    let valid: boolean = true;

    if (!poll.settings.reqLogin)
        valid = (await Tally.exists({ _id: poll._id, ip })) ? true : false;

    return valid;
};

export const vote = asyncHandler(async (req: AuthRequest, res: Response) => {
    const io: Server = req.app.get('io');

    const { clientIp: ip, uid } = req;
    const isAuth: boolean = req.isAuth ? req.isAuth : false;
    const { pid, name } = req.body;

    let opts = req.body.opts;

    if (!opts || !opts.length || !isMongoId(pid) || !uid || !ip) {
        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const poll = await Poll.findById(pid).select('_id settings opts').lean();
    if (!poll) {
        res.status(404).json({ message: 'Poll not found.' });
        return;
    }

    const message = await isValidVote(poll, opts, name, isAuth);
    if (message) {
        res.status(401).json({ message });
        return;
    }

    const successfulUpdate = await tryUpdate(poll, opts, uid, name, ip);
    if (successfulUpdate) {
        res.json({ message: 'Poll updated!' });
        return;
    } else if (successfulUpdate === false) {
        res.status(401).json({
            message: 'You have already voted on this poll.',
        });
        return;
    }

    const validIp = await isValidIp(poll, ip);
    if (!validIp) {
        res.status(409).json({
            message: 'Someone on your network has already voted on this poll.',
        });
        return;
    }

    await Tally.create({ uid, pid, opts, name, ip });
    await Poll.findByIdAndUpdate(pid, {
        $inc: { users: 1 },
    });

    res.json({ message: 'Vote casted.' });
    await emitUpdate(io, poll);
});
