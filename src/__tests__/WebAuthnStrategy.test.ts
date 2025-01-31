import { WebAuthnStrategy } from "../";
import type { WebAuthnUser, UserStore, ChallengeStore } from "../types";
import { Request } from "express";
import { v4 as uuidv4 } from "uuid";
import {AuthenticationResponseJSON, RegistrationResponseJSON} from "@simplewebauthn/server";

class MockUserStore implements UserStore {
    private users: Record<string, WebAuthnUser> = {};

    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        return Object.values(this.users).find(user =>
            byID ? user.userID === identifier : user.username === identifier
        );
    }

    async save(user: WebAuthnUser): Promise<void> {
        this.users[user.userID] = user;
    }
}

class MockChallengeStore implements ChallengeStore {
    private challenges: Record<string, string> = {};

    async get(userID: string): Promise<string | undefined> {
        return this.challenges[userID];
    }

    async save(userID: string, challenge: string): Promise<void> {
        this.challenges[userID] = challenge;
    }

    async delete(userID: string): Promise<void> {
        delete this.challenges[userID];
    }
}

describe("WebAuthnStrategy", () => {
    let strategy: WebAuthnStrategy;
    let userStore: MockUserStore;
    let challengeStore: MockChallengeStore;

    beforeEach(() => {
        userStore = new MockUserStore();
        challengeStore = new MockChallengeStore();
        strategy = new WebAuthnStrategy({
            rpID: "localhost",
            rpName: "Test RP",
            userStore,
            challengeStore,
        });
    });

    test("should generate registration challenge", async () => {
        const req = {} as Request;
        const username = "testuser";

        const options = await strategy.registerChallenge(req, username);
        expect(options).toHaveProperty("challenge");
        expect(typeof options.challenge).toBe("string");
    });

    // test("should complete registration callback successfully", async () => {
    //     const req = {} as Request;
    //     const username = "testuser";
    //     const userID = uuidv4();
    //
    //     await userStore.save({ userID, username, passkeys: [] });
    //     await challengeStore.save(userID, "mocked-challenge");
    //
    //     const credential: RegistrationResponseJSON = {
    //         id: "test-id",
    //         rawId: "test-raw-id",
    //         response: {
    //             attestationObject: "mocked-attestation-object",
    //             clientDataJSON: "mocked-client-data-json",
    //         },
    //         clientExtensionResults: {},
    //         type: "public-key",
    //     };
    //
    //     await expect(strategy.registerCallback(req, username, credential)).rejects.toThrow(
    //         "Registration failed"
    //     );
    // });

    test("should generate authentication challenge", async () => {
        const req = {} as Request;
        const username = "testuser";
        const userID = uuidv4();

        await userStore.save({
            userID,
            username,
            passkeys: [
                {
                    id: "test-id",
                    publicKey: new Uint8Array(),
                    counter: 0,
                    transports: ["internal"],
                },
            ],
        });

        const options = await strategy.loginChallenge(req, username);
        expect(options).toHaveProperty("challenge");
        expect(typeof options.challenge).toBe("string");
    });

    test("should fail authentication when no user exists", async () => {
        const req = {} as Request;
        const username = "nonexistentuser";

        await expect(strategy.loginChallenge(req, username)).rejects.toThrow("User not found");
    });

    test("should fail registration for missing username", async () => {
        const req = {} as Request;

        await expect(strategy.registerChallenge(req, "")).rejects.toThrow("Username required");
    });

    test("should handle missing user during login callback", async () => {
        const req = {} as Request;
        const username = "nonexistentuser";
        const credential: AuthenticationResponseJSON = {
            id: "test-id",
            rawId: "test-raw-id",
            response: {
                authenticatorData: "mocked-authenticator-data",
                clientDataJSON: "mocked-client-data-json",
                signature: "mocked-signature",
                userHandle: "mocked-user-handle",
            },
            clientExtensionResults: {},
            type: "public-key",
        };

        await expect(strategy.loginCallback(req, username, credential)).rejects.toThrow(
            "User not found"
        );
    });

    test("should handle missing challenge during login callback", async () => {
        const req = {} as Request;
        const username = "testuser";
        const userID = uuidv4();

        await userStore.save({
            userID,
            username,
            passkeys: [
                {
                    id: "test-id",
                    publicKey: new Uint8Array(),
                    counter: 0,
                    transports: ["internal"],
                },
            ],
        });

        const credential: AuthenticationResponseJSON = {
            id: "test-id",
            rawId: "test-raw-id",
            response: {
                authenticatorData: "mocked-authenticator-data",
                clientDataJSON: "mocked-client-data-json",
                signature: "mocked-signature",
                userHandle: "mocked-user-handle",
            },
            clientExtensionResults: {},
            type: "public-key",
        };

        await expect(strategy.loginCallback(req, username, credential)).rejects.toThrow(
            "Challenge not found"
        );
    });

    test("should handle missing passkey during login callback", async () => {
        const req = {} as Request;
        const username = "testuser";
        const userID = uuidv4();

        await userStore.save({ userID, username, passkeys: [] });
        await challengeStore.save(userID, "mocked-challenge");

        const credential: AuthenticationResponseJSON = {
            id: "test-id",
            rawId: "test-raw-id",
            response: {
                authenticatorData: "mocked-authenticator-data",
                clientDataJSON: "mocked-client-data-json",
                signature: "mocked-signature",
                userHandle: "mocked-user-handle",
            },
            clientExtensionResults: {},
            type: "public-key",
        };

        await expect(strategy.loginCallback(req, username, credential)).rejects.toThrow(
            "Passkey not found"
        );
    });

    test("should reject calls to authenticate() directly", async () => {
        const req = {} as Request;
        expect(() => strategy.authenticate(req)).toThrow(
            "Use registerChallenge, registerCallback, loginChallenge, or loginCallback instead."
        );
    });
});