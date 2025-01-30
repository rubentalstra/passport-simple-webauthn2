import { saveChallenge, getChallenge, clearChallenge, resetChallengeStore } from "../../strategy/challengeStore";

describe("Challenge Store Functions", () => {
    const userId = Buffer.from([1, 2, 3, 4]).toString("base64url");
    const challenge = "test-challenge";

    beforeEach(async () => {
        resetChallengeStore(); // Ensure fresh state before each test
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    it("should save and retrieve a challenge", async () => {
        await saveChallenge(userId, challenge);
        const retrievedChallenge = await getChallenge(userId);
        expect(retrievedChallenge).toBe(challenge);
    });

    it("should return null if challenge does not exist", async () => {
        const retrievedChallenge = await getChallenge(userId);
        expect(retrievedChallenge).toBeNull();
    });

    it("should clear a saved challenge", async () => {
        await saveChallenge(userId, challenge);
        await clearChallenge(userId);
        const retrievedChallenge = await getChallenge(userId);
        expect(retrievedChallenge).toBeNull();
    });

    it("should overwrite an existing challenge when saving a new one", async () => {
        await saveChallenge(userId, "old-challenge");
        await saveChallenge(userId, challenge); // Overwrites old challenge
        const retrievedChallenge = await getChallenge(userId);
        expect(retrievedChallenge).toBe(challenge);
    });

    it("should reset the challenge store and remove all challenges", async () => {
        await saveChallenge(userId, challenge);
        resetChallengeStore();
        const retrievedChallenge = await getChallenge(userId);
        expect(retrievedChallenge).toBeNull();
    });
});