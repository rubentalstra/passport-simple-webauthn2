import mongoose, { Schema, Document } from "mongoose";

export interface IUser extends Document {
    userID: string;
    username: string;
    passkeys: {
        id: string;
        publicKey: Buffer; // Stored as a Buffer for direct use in WebAuthn verification
        counter: number;
        transports: string[];
    }[];
}

const UserSchema = new Schema<IUser>({
    userID: { type: String, required: true, unique: true, index: true },
    username: { type: String, required: true, unique: true, index: true },
    passkeys: {
        type: [
            {
                id: { type: String, required: true },
                publicKey: { type: Buffer, required: true },
                counter: { type: Number, required: true },
                transports: { type: [String], required: true },
            },
        ],
        default: [],
    },
});

export const User = mongoose.model<IUser>("User", UserSchema);