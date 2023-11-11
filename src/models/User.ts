import { Document, Error, model, Schema } from 'mongoose';
import bcrypt from 'bcrypt';
import isEmail from 'validator/lib/isEmail';
import isStrongPassword from 'validator/lib/isStrongPassword';

const FIVE_MINUTES = 60 * 5;

/**
* This will allow different types of users in the same collection.
* Planning on Google authentication.
*/
const userSchema = new Schema({
	tokens: {
		type: [String],
		default: []
	},
	secrete: {
		type: new Schema({
			__t: {
				type: String,
				enum: ['forgot_password', 'email_verification'],
				required: true
			}
		}, { _id: true }),
		expires: FIVE_MINUTES
	}
}, { timestamps: true });
const User = model('User', userSchema);

const authUserSchema = userSchema.clone();
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
	}
});

authUserSchema.pre('save', async function(this: Document & { password: string }, next) {
	// password is not modified, so hashing is not needed!
	if (!this.isModified('password')) {
		return next();
	}

	try {
		const hashedPassword = await bcrypt.hash(this.password, 10);

		// Swap plain text password to its hashed version.
		this.password = hashedPassword;

		next();
	} catch (error) {
		return next(error as Error);
	}
});

const EmailPasswordAuth = User.discriminator('email_password', authUserSchema);

export { User, EmailPasswordAuth };
