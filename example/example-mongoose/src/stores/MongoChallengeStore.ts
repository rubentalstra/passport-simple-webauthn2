import { Challenge } from "../models/Challenge";
import type { ChallengeStore } from "../../../../dist/types";

export class MongoChallengeStore implements ChallengeStore {
    async get(userId: string): Promise<string | undefined> {
        try {
            const challenge = await Challenge.findOne({ userId }).lean().exec();
            return challenge?.challenge;
        } catch (error) {
            console.error(`❌ Error fetching challenge for userId ${userId}:`, error);
            return undefined;
        }
    }

    async save(userId: string, challenge: string): Promise<void> {
        try {
            await Challenge.findOneAndUpdate(
                { userId },
                { challenge, createdAt: new Date() },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            ).exec();
        } catch (error) {
            console.error(`❌ Error saving challenge for userId ${userId}:`, error);
        }
    }

    async delete(userId: string): Promise<void> {
        try {
            await Challenge.deleteOne({ userId }).exec();
        } catch (error) {
            console.error(`❌ Error deleting challenge for userId ${userId}:`, error);
        }
    }
}