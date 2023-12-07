import { Schema, Types, model } from 'mongoose';
import { User } from './User';

// Settings shared between the two types of polls
const sharedSettings = {
    deadline: {
        type: Date,
    },
    reqLogin: {
        type: Boolean,
        default: false,
    },
    reqNames: {
        type: Boolean,
        default: false,
    },
    allowEdit: {
        type: Boolean,
        default: false,
    },
    default: () => ({}),
};

const strInputValidator = {
    validate: (value: string) => value.length <= 255,
    message: 'String exceeds maximum length of 255 characters.',
};

const uidField = {
    type: Types.ObjectId,
    ref: 'User',
    required: true,
    validate: async (value: Types.ObjectId) => {
        return await User.exists({ _id: value });
    },
    message: 'User does not exist.',
};

const choiceSchema = new Schema({
    _id: {
        type: Number,
    },
    opt: {
        type: String,
        validator: strInputValidator,
    },
    tally: {
        type: Number,
        default: 0,
    },
    voters: [
        new Schema({
            uid: uidField,
            points: {
                type: Number,
                validator: {
                    validate: (value: number) => value > 0 && value <= 10,
                    message: 'Points out of range.',
                },
                default: 1,
            },
        }),
    ],
});

const pollSchema = new Schema(
    {
        admin: uidField,
        question: {
            type: String,
            validator: strInputValidator,
            required: true,
        },
        choices: {
            type: [choiceSchema],
            validator: {
                validate: (value: Schema[]) =>
                    value.length > 0 && value.length <= 10,
                message: 'Polls require 1-10 choices.',
            },
        },
        settings: {
            type: new Schema({
                ...sharedSettings,
                allowMultiple: {
                    type: Boolean,
                    default: false,
                },
            }),
        },
        __t: {
            type: String,
            enum: ['Base', 'Ranking'],
            default: 'Base',
        },
    },
    { timestamps: true },
);
pollSchema.pre('save', function (next) {
    this.choices.forEach((choice, i) => {
        choice._id = i;
    });
    next();
});

export const Poll = model('Poll', pollSchema);

const rankingPollSchema = new Schema({
    settings: {
        type: new Schema(sharedSettings),
    },
});

export const RankingPoll = Poll.discriminator('Ranking', rankingPollSchema);
