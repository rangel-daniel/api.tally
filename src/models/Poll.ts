import { Document, Schema, Types, model } from 'mongoose';
import { User } from './User';

const strInputValidator = {
    validator: (value: string) => {
        return value.length > 0 && value.length <= 255;
    },
    message: 'String is empty or exceeds maximum length of 255 characters.',
};

export const uidField = {
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
    opts: {
        _id: Types.ObjectId;
        opt: string;
    }[];
    settings: {
        deadline?: Date;
        reqLogin: boolean;
        reqNames: boolean;
        allowEdit: boolean;
        allowMultiple: boolean;
    };
}

const pollSchema = new Schema<PollDocument>(
    {
        admin: uidField,
        question: {
            type: String,
            validate: strInputValidator,
            required: true,
        },
        opts: {
            type: [
                new Schema({
                    opt: {
                        type: String,
                        validator: strInputValidator,
                        required: true,
                    },
                }),
            ],
            validate: {
                validator: (
                    value: {
                        _id: Types.ObjectId;
                        opt: string;
                    }[],
                ) => {
                    return value.length > 1 && value.length <= 10;
                },
                message: 'Polls require 2-10 choices.',
            },
            required: true,
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
    },
    { timestamps: true },
);

export const Poll = model('Poll', pollSchema);
