import { Document, Schema, Types, model } from 'mongoose';
import { User } from './User';

const strInputValidator = {
    validator: (value: string) => {
        return value.length > 0 && value.length <= 255;
    },
    message: 'String is empty or exceeds maximum length of 255 characters.',
};

const uidField = {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    validate: {
        validator: async (value: Types.ObjectId) => {
            return await User.exists({ _id: value });
        },
        message: 'User does not exist.',
    },
};

export interface PollDocument extends Document {
    admin: Types.ObjectId;
    question: string;
    choices: {
        opt: string;
        tally: number;
    }[];
    settings: {
        deadline?: Date;
        reqLogin: boolean;
        reqNames: boolean;
        allowEdit: boolean;
        allowMultiple: boolean;
    };
    voters: {
        uid: Types.ObjectId;
        name?: string;
        sel: Types.ObjectId[];
    }[];
}

const pollSchema = new Schema<PollDocument>(
    {
        admin: uidField,
        question: {
            type: String,
            validate: strInputValidator,
            required: true,
        },
        choices: {
            type: [
                new Schema({
                    opt: {
                        type: String,
                        validator: strInputValidator,
                    },
                    tally: {
                        type: Number,
                        default: 0,
                    },
                }),
            ],
            validate: {
                validator: function (value: any) {
                    return value && value.length > 1 && value.length <= 10;
                },
                message: 'Polls require 2-10 choices.',
            },
        },
        settings: {
            type: new Schema(
                {
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
                    allowMultiple: {
                        type: Boolean,
                        default: false,
                    },
                },
                { _id: false },
            ),
            default: () => ({}),
        },
        voters: [
            new Schema(
                {
                    uid: uidField,
                    name: {
                        type: String,
                    },
                    sel: {
                        type: [Types.ObjectId],
                    },
                },
                { _id: false },
            ),
        ],
    },
    { timestamps: true },
);

export const Poll = model('Poll', pollSchema);
