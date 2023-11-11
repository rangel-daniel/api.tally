import dotenv from 'dotenv';
import express from 'express';
import { connection } from 'mongoose';

import { root, wildcard } from './routes/rootRoutes';
import auth from './routes/authRoutes';
import connectDb from './config/connectDb';
import errorHandler from './middleware/errorHandler';

dotenv.config();

const app = express();
const PORT = 3000;

connectDb();

app.use(express.json());

app.use('/', root);
app.use('/auth', auth);
app.use('*', wildcard);

app.use(errorHandler);

connection.once('open', () => {
	console.log('DB connection successful!');

	app.listen(PORT, () => {
		console.log(`${process.env.NODE_ENV} Server running on PORT ${PORT}`);
	});
});

connection.on('error', error => {
	console.error((error as Error).message);
});
