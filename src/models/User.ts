import { Model, model, Schema, Types } from 'mongoose';
import bcrypt from 'bcrypt';
import isEmail from 'validator/lib/isEmail';
import isStrongPassword from 'validator/lib/isStrongPassword';

interface BaseUser extends Document {
	_id: Types.ObjectId,
	tokens: Array<string>;
}

export interface EmailPasswordUser extends BaseUser {
	email: string;
	tempEmail?: string;
	password: string;
	name: string;
}

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
		required: [true, 'You must enter an email.'],
		unique: true,
		trim: true,
		validate: {
			validator: (value: string) => { return isEmail(value); },
			message: 'Invalid email.'
		}
	},
	tempEmail: {
		type: String,
		trim: true,
		validate: {
			validator: (value: string) => { return isEmail(value) || value === 'new'; },
			message: 'Invalid email.'
		},
		default: 'new'
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
		trim: true,
		validate: {
			validator: (value: string) => { return value.length >= 5 && value.length <= 50; },
			message: 'Invalid name.'
		}
	}
});


authUserSchema.pre('save', async function(next) {
	if (this.isModified('password')) {
		try {
			const hashedPassword = await bcrypt.hash(this.password, 10);
			this.password = hashedPassword;
		} catch (error) {
			return next(error as Error);
		}
	}
});


const EmailPasswordAuth = User.discriminator('email_password', authUserSchema);

export { User, EmailPasswordAuth };
