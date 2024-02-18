import { model, Schema, Types } from 'mongoose';
import bcrypt from 'bcrypt';
import isEmail from 'validator/lib/isEmail';
import isStrongPassword from 'validator/lib/isStrongPassword';

const ONE_MONTH = 60 * 60 * 30;

interface UserDoc extends Document {
    _id: Types.ObjectId;
    token?: string;
}

export interface GuestUserDoc extends UserDoc {
    expireAt: Date;
}

export interface AuthUserDoc extends UserDoc {
    email: string;
    tempEmail?: string;
    password: string;
    name: string;
    isVerified: boolean;
}

const userSchema = new Schema<UserDoc>({}, { timestamps: true });

const guestUserSchema = new Schema<GuestUserDoc>({
    expireAt: { type: Date, expires: ONE_MONTH, default: Date.now },
    token: { type: String },
});

const authUserSchema = new Schema<AuthUserDoc>({
    email: {
        type: String,
        required: [true, 'Missing email.'],
        unique: true,
        trim: true,
        validate: {
            validator: (value: string) => {
                return isEmail(value);
            },
            message: 'Invalid email.',
        },
    },
    tempEmail: {
        type: String,
        trim: true,
        validate: {
            validator: (value: string) => {
                return isEmail(value);
            },
            message: 'Invalid email.',
        },
    },
    password: {
        type: String,
        required: [true, 'Missing password.'],
        validate: {
            validator: (value: string) => {
                return isStrongPassword(value);
            },
            message: 'Invalid password.',
        },
    },
    name: {
        type: String,
        required: [true, 'Missing name.'],
        trim: true,
        validate: {
            validator: (value: string) => {
                return value.length >= 3 && value.length <= 50;
            },
            message: 'Invalid name.',
        },
    },
    isVerified: { type: Boolean, default: false },
    token: { type: String },
});

// Password hashing
authUserSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        try {
            const hashedPassword = await bcrypt.hash(this.password, 10);
            this.password = hashedPassword;
        } catch (error) {
            return next(error as Error);
        }
    }
});

const User = model('User', userSchema);

const AuthUser = User.discriminator('auth', authUserSchema);
const GuestUser = User.discriminator('guest', guestUserSchema);

export { User, AuthUser, GuestUser };
