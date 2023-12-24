import { Request, Response } from 'express';
import { Poll } from '../models/Poll';
import asyncHandler from 'express-async-handler';
import { AuthRequest } from '../middleware/verifyJwt';

export const createPoll = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const admin = req.user?.uid;

        if (!admin) {
            res.status(400).json({ message: 'Missing user.' });
            return;
        }

        const { question, choices, settings } = req.body;

        await Poll.create({ admin, question, choices, settings });

        res.json({ message: 'Poll created!' });
    },
);

export const getPolls = asyncHandler(
    async (req: AuthRequest, res: Response) => {
        const admin = req.user?.uid;

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
    const admin = req.user?.uid;
    const { pid } = req.params;

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

export const getPoll = asyncHandler(async (req: Request, res: Response) => {
    const { pid } = req.params;

    const poll = await Poll.findById(pid).lean();

    if (!poll) {
        res.status(404).json({ message: 'Poll does not exist.' });
        return;
    }

    res.json(poll);
});
