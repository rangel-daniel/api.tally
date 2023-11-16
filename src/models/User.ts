import { Model, model, Schema, Types } from 'mongoose';
import bcrypt from 'bcrypt';
import isEmail from 'validator/lib/isEmail';
import isStrongPassword from 'validator/lib/isStrongPassword';
import { sendEmail } from '../utils/email';

interface BaseUser {
	tokens: Array<string>;
}

interface EmailPasswordUser extends BaseUser {
	email: string;
	password: string;
	name: string;
	secrete: {
		type: 'activate' | 'password',
		_id?: Types.ObjectId
	}
}

const FIVE_MINUTES = 60 * 5;
/**
* This will allow different types of users in the same collection.
* Planning on Google authentication.
*/
const userSchema = new Schema<BaseUser, Model<BaseUser>>({
	tokens: {
		type: [String],
		default: []
	},
}, { timestamps: true });
const User = model('User', userSchema);

const authUserSchema = new Schema<EmailPasswordUser, Model<EmailPasswordUser>>(userSchema.clone());
authUserSchema.add({
	email: {
		type: String,
		unique: true,
		required: [true, 'You must enter an email.'],
		validate: {
			validator: (value: string) => { return isEmail(value); },
			message: 'Invalid email.'
		}
	},
	password: {
		type: String,
		required: [true, 'You must enter a password.'],
		validate: {
			validator: (value: string) => { return isStrongPassword(value); },
			message: 'Invalid password.'
		}
	},
	name: {
		type: String,
		required: [true, 'You must enter a name.'],
		validate: {
			validator: (value: string) => { return value.length >= 5 && value.length <= 50; },
			message: 'Invalid name.'
		}
	},
	secrete: {
		type: new Schema({
			type: {
				type: String,
				enum: {
					values: ['forgot_password', 'activate'],
					message: 'Secrete type provided is not supported.'
				},
				required: [true, 'Missing type.']
			},
		}, { _id: true }),
		expires: FIVE_MINUTES
	}
});


authUserSchema.pre('save', async function(next) {
	try {

		if (this.isModified('password')) {
			const hashedPassword = await bcrypt.hash(this.password, 10);
			this.password = hashedPassword;
		}

		if (this.isModified('email')) {
			this.secrete = { type: 'activate' };

			const userInfo = {
				_id: this._id,
				name: this.name,
				email: this.email
			};

			const secrete = {
				type: this.secrete.type,
				_id: this.secrete._id as Types.ObjectId
			};

			await sendEmail(userInfo, secrete);
		}

	} catch (error) {
		return next(error as Error);
	}
});


const EmailPasswordAuth = User.discriminator('email_password', authUserSchema);

export { User, EmailPasswordAuth };
