import mongoose, { Schema, Document } from "mongoose";

// The IUser interface does not include a custom userID; MongoDB generates _id automatically.
export interface IUser extends Document {
    username: string;
    passkeys: {
        id: string;
        publicKey: Buffer; // Stored as a Buffer for direct use in WebAuthn verification
        counter: number;
        transports: string[];
    }[];
}

const UserSchema = new Schema<IUser>({
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