
import { saveChallenge, getChallenge, clearChallenge } from "../../index";
import type { Request } from "express";

describe("Challenge Store Functions", () => {
    let reqMock: Partial<Request>;
    const userId = "dXNlcklk"; // base64url-encoded user ID
    const challenge = "test-challenge";

    beforeEach(() => {
        reqMock = {};
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    it("should save a challenge", async () => {
        await saveChallenge(reqMock as Request, userId, challenge);

        // Since it's an in-memory store, access the internal Map directly
        // Assuming the challengeStore is exported for testing purposes
        // Alternatively, you can test getChallenge to verify save
        // Here, we'll use getChallenge

        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBe(challenge);
    });

    it("should retrieve a saved challenge", async () => {
        // First, save a challenge
        await saveChallenge(reqMock as Request, userId, challenge);

        // Then, retrieve it
        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBe(challenge);
    });

    it("should return null if challenge does not exist", async () => {
        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBeNull();
    });

    it("should clear a saved challenge", async () => {
        // Save a challenge first
        await saveChallenge(reqMock as Request, userId, challenge);

        // Clear the challenge
        await clearChallenge(reqMock as Request, userId);

        // Attempt to retrieve it
        const retrievedChallenge = await getChallenge(reqMock as Request, userId);
        expect(retrievedChallenge).toBeNull();
    });
});