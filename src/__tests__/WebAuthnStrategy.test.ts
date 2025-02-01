import { WebAuthnStrategy } from "../index";
import type { WebAuthnUser, UserStore, ChallengeStore } from "../types";
import { Request } from "express";
import { v4 as uuidv4 } from "uuid";
import {
    AuthenticationResponseJSON,
    RegistrationResponseJSON,
} from "@simplewebauthn/server";

class MockUserStore implements UserStore {
    private users: Record<string, WebAuthnUser> = {};

    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        return Object.values(this.users).find(user =>
            byID ? user.id === identifier : user.username === identifier
        );
    }

    async save(user: WebAuthnUser): Promise<WebAuthnUser> {
        // If an id isn't provided, generate one.
        if (!user.id) {
            user.id = uuidv4();
        }
        this.users[user.id] = user;
        return user;
    }
}

class MockChallengeStore implements ChallengeStore {
    private challenges: Record<string, string> = {};

    async get(userId: string): Promise<string | undefined> {
        return this.challenges[userId];
    }

    async save(userId: string, challenge: string): Promise<void> {
        this.challenges[userId] = challenge;
    }

    async delete(userId: string): Promise<void> {
        delete this.challenges[userId];
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
        // Provide a path that indicates registration
        const req = { path: "/register" } as Request;
        const username = "testuser";

        const options = await strategy.registerChallenge(req, username);
        expect(options).toHaveProperty("challenge");
        expect(typeof options.challenge).toBe("string");
    });

    test("should complete registration callback and fail verification", async () => {
        const req = { path: "/register" } as Request;
        const username = "testuser";
        const userID = uuidv4();

        await userStore.save({ id: userID, username, passkeys: [] });
        await challengeStore.save(userID, "mocked-challenge");

        const credential: RegistrationResponseJSON = {
            id: "test-id",
            rawId: "test-raw-id",
            response: {
                attestationObject: "mocked-attestation-object",
                clientDataJSON: "mocked-client-data-json",
            },
            clientExtensionResults: {},
            type: "public-key",
        };

        await expect(strategy.registerCallback(req, username, credential)).rejects.toThrow(
            "Credential ID was not base64url-encoded"
        );
    });

    test("should generate authentication challenge", async () => {
        // Provide a path that indicates login
        const req = { path: "/login" } as Request;
        const username = "testuser";
        const userID = uuidv4();

        await userStore.save({
            id: userID,
            username,
            passkeys: [
                {
                    id: "test-id",
                    publicKey: new Uint8Array(), // For testing, an empty Uint8Array
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
        const req = { path: "/login" } as Request;
        const username = "nonexistentuser";

        await expect(strategy.loginChallenge(req, username)).rejects.toThrow("User not found");
    });

    test("should fail registration for missing username", async () => {
        const req = {} as Request;

        await expect(strategy.registerChallenge(req, "")).rejects.toThrow("Username required");
    });

    test("should handle missing user during login callback", async () => {
        const req = { path: "/login" } as Request;
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
        const req = { path: "/login" } as Request;
        const username = "testuser";
        const userID = uuidv4();

        await userStore.save({
            id: userID,
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

        // No challenge saved for this user
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
        const req = { path: "/login" } as Request;
        const username = "testuser";
        const userID = uuidv4();

        await userStore.save({ id: userID, username, passkeys: [] });
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

    // Uncomment if needed:
    // test("should reject calls to authenticate() with an invalid path", async () => {
    //     // Using a path that doesn't contain "register" or "login" will trigger the error.
    //     const req = { path: "/invalid" } as Request;
    //     expect(() => strategy.authenticate(req)).toThrow(
    //         "Could not infer mode. Please ensure the URL contains either register or login."
    //     );
    // });
});