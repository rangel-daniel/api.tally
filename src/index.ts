import dotenv from 'dotenv';
import express from 'express';
import { connection } from 'mongoose';
import http from 'http';

import { root, wildcard } from './routes/root';
import auth from './routes/auth';
import poll from './routes/poll';

import connectDb from './config/connectDb';
import errorHandler from './middleware/errorHandler';
import cookieParser from 'cookie-parser';
import path from 'path';
import requestIp from 'request-ip';
import socketIO from 'socket.io';
import cors from 'cors';
import { corsOptions } from './config/allowedOrigins';

const PORT = 3000;
const app = express();
const server = http.createServer(app);
const io = new socketIO.Server(server);

app.set('io', io);

dotenv.config();
connectDb();
app.use(cors(corsOptions));
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

    io.on('connection', (socket: socketIO.Socket) => {
        console.log('New user');
        socket.on('joinPoll', (pid: string) => {
            socket.join(pid);
        });
    });

    app.listen(PORT, () => {
        console.log(`${process.env.NODE_ENV} Server running on PORT ${PORT}`);
    });
});

connection.on('error', (error) => {
    console.error((error as Error).message);
});
