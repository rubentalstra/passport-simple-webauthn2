import mongoose, { Schema, Document } from "mongoose";

export interface IUser extends Document {
    userID: string;
    username: string;
    passkeys: {
        id: string;
        publicKey: Buffer;
        counter: number;
        transports: string[];
    }[];
}

const UserSchema = new Schema<IUser>({
    userID: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    passkeys: [
        {
            id: { type: String, required: true },
            publicKey: {
                type: Buffer,
                required: true,
                set: (val: Uint8Array | Buffer) => Buffer.isBuffer(val) ? val : Buffer.from(val)
            },
            counter: { type: Number, required: true },
            transports: { type: [String], required: true },
        },
    ],
});

export const User = mongoose.model<IUser>("User", UserSchema);