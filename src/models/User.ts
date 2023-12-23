import { Model, model, Schema, Types } from 'mongoose';
import bcrypt from 'bcrypt';
import isEmail from 'validator/lib/isEmail';
import isStrongPassword from 'validator/lib/isStrongPassword';

interface GuestUserDoc extends Document {
    _id: Types.ObjectId;
    tokens: Array<string>;
}

const guestUserSchema = new Schema<GuestUserDoc, Model<GuestUserDoc>>(
    {
        tokens: {
            type: [String],
            default: [],
        },
    },
    { timestamps: true },
);

export interface AuthUserDoc extends GuestUserDoc {
    email: string;
    tempEmail?: string;
    password: string;
    name: string;
}

const authUserSchema = new Schema<AuthUserDoc>({
    email: {
        type: String,
        required: [true, 'You must enter an email.'],
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
                return isEmail(value) || value === 'new';
            },
            message: 'Invalid email.',
        },
        default: 'new',
    },
    password: {
        type: String,
        required: [true, 'You must enter a password.'],
        validate: {
            validator: (value: string) => {
                return isStrongPassword(value);
            },
            message: 'Invalid password.',
        },
    },
    name: {
        type: String,
        required: [true, 'You must enter a name.'],
        trim: true,
        validate: {
            validator: (value: string) => {
                return value.length >= 5 && value.length <= 50;
            },
            message: 'Invalid name.',
        },
    },
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

const User = model('User', guestUserSchema);

const AuthUser = User.discriminator('email_password', authUserSchema);

export { User, AuthUser };
