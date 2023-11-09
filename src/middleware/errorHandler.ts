import { Request, Response } from 'express';

const errorHandler = async (error: Error, req: Request, res: Response) => {
	const status = res.statusCode || 500;

	const { method, url } = req;
	const { message, name } = error;

	if (process.env.NODE_ENV === 'Dev') {
		console.error(error.stack);
	}

	return res.status(status).json({ name, message, method, url });
};

export default errorHandler;
