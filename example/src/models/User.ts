// src/models/User.ts

import mongoose, { Document, Schema } from 'mongoose';

export interface UserPasskey {
    id: string; // Credential ID (Base64-encoded)
    publicKey: Buffer;
    counter: number;
    transports: string[];
    deviceType: string;
    backedUp: boolean;
    webauthnUserID: string;
    user: mongoose.Types.ObjectId;
}

export interface UserModel extends Document {
    id: string;
    username: string;
    passkeys: UserPasskey[];
}

const PasskeySchema: Schema = new Schema({
    id: { type: String, required: true },
    publicKey: { type: Buffer, required: true },
    counter: { type: Number, required: true },
    transports: [{ type: String }],
    deviceType: { type: String },
    backedUp: { type: Boolean, default: false },
    webauthnUserID: { type: String, required: true },
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
});

const UserSchema: Schema = new Schema({
    username: { type: String, required: true, unique: true },
    passkeys: [PasskeySchema],
});

UserSchema.virtual('id').get(function () {
    return this.id.toHexString();
});

UserSchema.set('toJSON', {
    virtuals: true,
});

export default mongoose.model<UserModel>('User', UserSchema);