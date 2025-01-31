// src/models/User.ts

import mongoose, { Document, Schema } from 'mongoose';

export interface Passkey {
    id: string; // Credential ID (Base64-encoded)
    publicKey: Buffer;
    counter: number;
    transports: string[];
    deviceType: string;
    backedUp: boolean;
}

export interface UserModel extends Document {
    username: string;
    passkeys: Passkey[];
}

const PasskeySchema: Schema = new Schema({
    id: { type: String, required: true }, // Stored as Base64 string
    publicKey: { type: Buffer, required: true },
    counter: { type: Number, required: true },
    transports: [{ type: String }],
    deviceType: { type: String },
    backedUp: { type: Boolean, default: false },
});

const UserSchema: Schema = new Schema({
    username: { type: String, required: true, unique: true },
    passkeys: [PasskeySchema],
});

export default mongoose.model<UserModel>('User', UserSchema);