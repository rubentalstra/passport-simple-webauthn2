import { Challenge } from "../models/Challenge";
import type { ChallengeStore } from "passport-simple-webauthn2";

export class MongoChallengeStore implements ChallengeStore {
    async get(userID: string): Promise<string | undefined> {
        const challenge = await Challenge.findOne({ userID }).exec();
        return challenge?.challenge;
    }

    async save(userID: string, challenge: string): Promise<void> {
        await Challenge.findOneAndUpdate({ userID }, { challenge }, { upsert: true, new: true });
    }

    async delete(userID: string): Promise<void> {
        await Challenge.deleteOne({ userID }).exec();
    }
}