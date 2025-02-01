import mongoose, { Schema, Document } from "mongoose";

export interface IChallenge extends Document {
    userID: string;
    challenge: string;
    createdAt: Date;
}

const ChallengeSchema = new Schema<IChallenge>({
    userID: { type: String, required: true, unique: true },
    challenge: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, index: { expires: "5m" } },
});

export const Challenge = mongoose.model<IChallenge>("Challenge", ChallengeSchema);