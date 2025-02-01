export interface ChallengeStore {
    get(userId: string): Promise<string | undefined>;
    save(userId: string, challenge: string): Promise<void>;
    delete(userId: string): Promise<void>;
}

export class InMemoryChallengeStore implements ChallengeStore {
    private challenges: Map<string, { challenge: string; createdAt: Date }> = new Map();

    async get(userId: string): Promise<string | undefined> {
        const record = this.challenges.get(userId);
        return record ? record.challenge : undefined;
    }

    async save(userId: string, challenge: string): Promise<void> {
        this.challenges.set(userId, { challenge, createdAt: new Date() });
    }

    async delete(userId: string): Promise<void> {
        this.challenges.delete(userId);
    }
}