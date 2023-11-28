import { Schema, Types, model } from 'mongoose';
import { v4 as uuid } from 'uuid';


const FIVE_MINUTES = 60 * 5;

const secreteSchema = new Schema({
	token: {
		type: String,
		default: uuid
	},
	type: {
		type: String,
		enum: {
			values: ['activate', 'password'],
			message: 'Secrete type provided is not supported.'
		},
		required: [true, 'Missing type.']
	},
	uid: {
		type: Types.ObjectId,
		ref: 'User',
		required: [true, 'Missing uid.']
	},
	expireAt: { type: Date, expires: FIVE_MINUTES, default: Date.now }
});

const Secrete = model('Secrete', secreteSchema);

export default Secrete;
