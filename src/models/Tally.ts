import { Schema, model } from 'mongoose';
import { uidField } from './Poll';

interface TallyDoc extends Document {
    uid: Schema.Types.ObjectId;
    pid: Schema.Types.ObjectId;
    opts: Schema.Types.ObjectId;
    ip: string;
    name?: string;
}

const tallySchema = new Schema<TallyDoc>({
    uid: uidField,
    pid: {
        type: Schema.Types.ObjectId,
        ref: 'Poll',
        required: true,
    },
    opts: {
        type: [Schema.Types.ObjectId],
        ref: 'Poll.opts',
        required: true,
    },
    name: {
        type: String,
        trim: true,
        validate: {
            validator: (value: string) => {
                return value.length && value.length <= 50;
            },
            message: 'Invalid name.',
        },
    },
    ip: {
        type: String,
        required: [true, 'Missing IP address.'],
    },
});

export const Tally = model('Tally', tallySchema);
