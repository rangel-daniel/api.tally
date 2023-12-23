import { Request, Response } from 'express';
import { Poll } from '../models/Poll';
import asyncHandler from 'express-async-handler';

export const createPoll = asyncHandler(async (req: Request, res: Response) => {
    const { admin, question, choices, settings } = req.body;

    await Poll.create({ admin, question, choices, settings });

    res.json({ message: 'Poll created!' });
});

export const getPollById = asyncHandler(async (req: Request, res: Response) => {
    const { _id } = req.params;

    const exists = await Poll.exists({ _id });

    if (!exists) {
        res.status(404).json({ message: 'Poll not found.' });
        return;
    }

    const poll = await Poll.findOne({ _id }).lean();

    res.json(poll);
});
