import { connect } from 'mongoose';

const connectDb = async () => {
	const URI = process.env.DB_URI || '';
	try {
		await connect(URI);
	} catch (error) {
		console.error((error as Error).message);
	}
};

export default connectDb;
