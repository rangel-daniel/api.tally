import dotenv from 'dotenv';
import express from 'express';
import { connection } from 'mongoose';

import { root, wildcard } from './routes/root';
import auth from './routes/auth';
import poll from './routes/poll';

import connectDb from './config/connectDb';
import errorHandler from './middleware/errorHandler';
import cookieParser from 'cookie-parser';
import path from 'path';
import requestIp from 'request-ip';

const PORT = 3000;
const app = express();

dotenv.config();
connectDb();
app.use(express.json());
app.use(cookieParser());
app.use(requestIp.mw());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use('/', root);
app.use('/auth', auth);
app.use('/poll', poll);
app.use('*', wildcard);

app.use(errorHandler);

connection.once('open', () => {
    console.log('DB connection successful!');

    app.listen(PORT, () => {
        console.log(`${process.env.NODE_ENV} Server running on PORT ${PORT}`);
    });
});

connection.on('error', (error) => {
    console.error((error as Error).message);
});
