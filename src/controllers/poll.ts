import { Request, Response } from 'express';
import { Poll } from '../models/Poll';
import { AuthRequest } from '../middleware/verifyJwt';
import asyncHandler from 'express-async-handler';
import { Tally } from '../models/Tally';

export const createPoll = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { uid: admin } = req;

        if (!admin) {
            res.status(400).json({ message: 'Missing user.' });
            return;
        }

        const { question, opts, settings } = req.body;

        await Poll.create({ admin, question, opts, settings });

        res.json({ message: 'Poll created!' });
    },
);

export const getPolls = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { uid: admin } = req;

        if (!admin) {
            res.status(400).json({ message: 'Missing user.' });
            return;
        }

        const polls = await Poll.find({ admin }).lean();

        if (!polls.length) {
            res.status(204);
        }

        res.json(polls);
    },
);

export const rmPoll = asyncHandler(async (req: AuthRequest, res: Response) => {
    const { pid } = req.params;
    const { uid: admin } = req;

    if (!admin || !pid) {
        res.status(400).json({ message: 'Missing data.' });
        return;
    }

    const { deletedCount } = await Poll.deleteOne({ admin, _id: pid });

    if (!deletedCount) {
        res.status(404).json({ message: 'Poll does not exist.' });
        return;
    }

    res.json({ message: 'Poll deleted.' });
});

export const resetPoll = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const { pid } = req.body;
        const { uid } = req;

        if (!uid || !pid) {
            res.status(400).json({ message: 'Missing data.' });
            return;
        }

        const poll = await Poll.exists({ _id: pid, admin: uid });

        if (!poll) {
            res.status(404).json({ message: 'Poll not found.' });
            return;
        }

        await Tally.deleteMany({ pid });
        res.json({ message: 'Poll reset successful.' });
    },
);

export const getPoll = asyncHandler(async (req: Request, res: Response) => {
    const { pid } = req.params;

    const poll = await Poll.findById(pid).lean();

    if (!poll) {
        res.status(404).json({ message: 'Poll does not exist.' });
        return;
    }

    res.json(poll);
});
