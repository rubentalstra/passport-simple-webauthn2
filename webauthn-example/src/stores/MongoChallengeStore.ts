import { Challenge } from "../models/Challenge";
import type { ChallengeStore } from "../../../dist/types";

export class MongoChallengeStore implements ChallengeStore {
    async get(userID: string): Promise<string | undefined> {
        try {
            const challenge = await Challenge.findOne({ userID }).lean().exec();
            return challenge?.challenge;
        } catch (error) {
            console.error(`❌ Error fetching challenge for userID ${userID}:`, error);
            return undefined;
        }
    }

    async save(userID: string, challenge: string): Promise<void> {
        try {
            await Challenge.findOneAndUpdate(
                { userID },
                { challenge },
                { upsert: true, new: true, setDefaultsOnInsert: true }
            ).exec();
        } catch (error) {
            console.error(`❌ Error saving challenge for userID ${userID}:`, error);
        }
    }

    async delete(userID: string): Promise<void> {
        try {
            await Challenge.deleteOne({ userID }).exec();
        } catch (error) {
            console.error(`❌ Error deleting challenge for userID ${userID}:`, error);
        }
    }
}