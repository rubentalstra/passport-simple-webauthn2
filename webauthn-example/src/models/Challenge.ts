import mongoose, { Schema, Document } from "mongoose";

export interface IChallenge extends Document {
    userID: string;
    challenge: string;
    createdAt: Date;
}

const ChallengeSchema = new Schema<IChallenge>({
    userID: { type: String, required: true, unique: true },
    challenge: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 300 }, // Auto-delete after 5 minutes
});

export const Challenge = mongoose.model<IChallenge>("Challenge", ChallengeSchema);