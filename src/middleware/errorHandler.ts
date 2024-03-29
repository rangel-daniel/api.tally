import { NextFunction, Request, Response } from 'express';
import { Error as MongoError } from 'mongoose';

/**
 * This look kinda rough right now.
 * Should clean up in the future if it gets any messier.
 * @description Can also handle validation errors from Mongo models to declutter controllers.
 * */
const errorHandler = async (
    error: Error,
    req: Request,
    res: Response,
    next: NextFunction,
) => {
    let status = 500;
    let body: { [key: string]: unknown } = {};

    if (process.env.NODE_ENV === 'Dev') {
        console.error(JSON.stringify(error), req.url);
    }

    if (error.name === 'MongoServerError') {
        const serverError = error as MongoError & {
            code: number;
            keyValue: { [key: string]: unknown };
        };
        const { code, keyValue } = serverError;

        if (code === 11000) {
            status = 409;
            const key = Object.keys(keyValue)[0];
            const value = keyValue[key];
            body = { message: `${key} ${value} is already in use.` };
        } else {
            body = { code, keyValue };
        }
    } else if (error instanceof MongoError.ValidationError) {
        status = 400;
        const errors = error.errors;

        for (const key in errors) {
            body[key] = (errors[key] as MongoError.ValidatorError).properties?.message;
        }
    } else {
        const { method, url } = req;
        const { message } = error;

        body = { method, url, message };
    }

    res.status(status).json(body);

    next(error);
};

export default errorHandler;
