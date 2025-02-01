import { ChallengeStore } from "./types";
import Redis from "ioredis";

export class RedisChallengeStore implements ChallengeStore {
    private redis: Redis;

    constructor(redisUrl: string) {
        this.redis = new Redis(redisUrl);
    }

    async get(userID: string): Promise<string | undefined> {
        return this.redis.get(`challenge:${userID}`);
    }

    async save(userID: string, challenge: string): Promise<void> {
        await this.redis.set(`challenge:${userID}`, challenge, "EX", 300); // 5 min expiry
    }

    async delete(userID: string): Promise<void> {
        await this.redis.del(`challenge:${userID}`);
    }
}