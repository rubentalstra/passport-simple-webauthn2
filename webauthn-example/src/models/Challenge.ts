import mongoose, { Schema, Document } from "mongoose";

export interface IChallenge extends Document {
    userID: string;
    challenge: string;
}

const ChallengeSchema = new Schema<IChallenge>({
    userID: { type: String, required: true, unique: true },
    challenge: { type: String, required: true },
});

export const Challenge = mongoose.model<IChallenge>("Challenge", ChallengeSchema);