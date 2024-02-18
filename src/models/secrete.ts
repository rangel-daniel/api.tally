import { Schema, Types, model } from 'mongoose';
import { v4 as uuid } from 'uuid';

const FIVE_MINUTES = 60 * 5;

const secreteSchema = new Schema({
    token: {
        type: String,
        default: uuid,
    },
    isPassword: {
        type: Boolean,
        default: false,
    },
    uid: {
        type: Types.ObjectId,
        ref: 'User',
        required: [true, 'Missing uid.'],
    },
    expireAt: { type: Date, expires: FIVE_MINUTES, default: Date.now },
});

const Secrete = model('Secrete', secreteSchema);

export default Secrete;
