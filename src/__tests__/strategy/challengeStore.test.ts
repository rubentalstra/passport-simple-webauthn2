import { saveChallenge, getChallenge, clearChallenge, resetChallengeStore } from "../../strategy/challengeStore";
import type { Request } from "express";

describe("Challenge Store Functions", () => {
    let reqMock: Partial<Request>;
    const userId = Buffer.from([1, 2, 3, 4]).toString("base64url");
    const challenge = "test-challenge";

    beforeEach(() => {
        reqMock = {};
        resetChallengeStore()
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    it("should save a challenge", async () => {
        await saveChallenge(reqMock as Request, userId, challenge);
        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBe(challenge);
    });

    it("should retrieve a saved challenge", async () => {
        await saveChallenge(reqMock as Request, userId, challenge);
        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBe(challenge);
    });

    it("should return null if challenge does not exist", async () => {
        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBeNull();
    });

    it("should clear a saved challenge", async () => {
        await saveChallenge(reqMock as Request, userId, challenge);
        await clearChallenge(reqMock as Request, userId);
        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBeNull(); // Should now return null
    });
});