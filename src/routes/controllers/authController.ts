import { Request, Response } from 'express';
import asyncHandler from 'express-async-handler';
import { EmailPasswordAuth } from '../../models/User';

export const registerUser = asyncHandler(async (req: Request, res: Response) => {
	const { email, password, name } = req.body;
	await EmailPasswordAuth.create({ email, password, name });

	res.json({ message: 'Successful registration!' });
});
