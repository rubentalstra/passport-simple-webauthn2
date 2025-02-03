import { WebAuthnStrategy } from "../src";
import type { WebAuthnUser, UserStore, ChallengeStore } from "../src";
import { Request } from "express";
import { v4 as uuidv4 } from "uuid";
import {
    AuthenticationResponseJSON,
    RegistrationResponseJSON,
} from "@simplewebauthn/server";

// We'll need to mock the external functions from @simplewebauthn/server
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} from "@simplewebauthn/server";

jest.mock("@simplewebauthn/server", () => ({
    generateRegistrationOptions: jest.fn(),
    verifyRegistrationResponse: jest.fn(),
    generateAuthenticationOptions: jest.fn(),
    verifyAuthenticationResponse: jest.fn(),
}));

// Helper: Decode a base64url string into UTF-8 text.
function decodeBase64URL(str: string): string {
    return Buffer.from(str, "base64url").toString("utf-8");
}

// Dummy data
const dummyChallengeBuffer = Buffer.from("dummy-challenge");
const dummyChallengeEncoded = dummyChallengeBuffer.toString("base64url"); // should be "ZHVtbXktY2hhbGxlbmdl"
const dummyCredentialID = "test-id";

const dummyRegistrationOptions = {
    challenge: dummyChallengeBuffer,
    rpName: "Test RP",
    rpID: "localhost",
    userID: Buffer.from("dummy-user-id", "utf-8"),
    userName: "test@example.com",
    attestationType: "none",
    excludeCredentials: [],
    authenticatorSelection: {
        userVerification: "required",
        residentKey: "required",
        authenticatorAttachment: "platform",
    },
};

const dummyAuthenticationOptions = {
    challenge: dummyChallengeBuffer,
    rpID: "localhost",
    userVerification: "required",
    allowCredentials: [
        {
            id: dummyCredentialID,
            type: "public-key",
            transports: ["internal"],
        },
    ],
};

const dummyRegistrationResponse: RegistrationResponseJSON = {
    id: dummyCredentialID,
    rawId: dummyCredentialID,
    response: {
        attestationObject: "mocked-attestation-object",
        clientDataJSON: "mocked-client-data-json",
    },
    clientExtensionResults: {},
    type: "public-key",
};

const dummyAuthenticationResponse: AuthenticationResponseJSON = {
    id: dummyCredentialID,
    rawId: dummyCredentialID,
    response: {
        authenticatorData: "mocked-authenticator-data",
        clientDataJSON: "mocked-client-data-json",
        signature: "mocked-signature",
        userHandle: "mocked-user-handle",
    },
    clientExtensionResults: {},
    type: "public-key",
};

// In-memory/mock implementations for the stores
class MockUserStore implements UserStore {
    private users: Record<string, WebAuthnUser> = {};

    async get(identifier: string, byID = false): Promise<WebAuthnUser | undefined> {
        return Object.values(this.users).find(user =>
            byID ? user.id === identifier : user.email === identifier
        );
    }

    async save(user: WebAuthnUser): Promise<WebAuthnUser> {
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

// Helper to create a dummy Request object.
function createRequest({
                           method = "GET",
                           path = "/",
                           body = {},
                           query = {},
                       }: Partial<Request>): Request {
    return {
        method,
        path,
        body,
        query,
    } as unknown as Request;
}

describe("WebAuthnStrategy", () => {
    let strategy: WebAuthnStrategy;
    let userStore: MockUserStore;
    let challengeStore: MockChallengeStore;

    beforeEach(() => {
        jest.clearAllMocks();
        userStore = new MockUserStore();
        challengeStore = new MockChallengeStore();
        strategy = new WebAuthnStrategy({
            rpID: "localhost",
            rpName: "Test RP",
            userStore,
            challengeStore,
            debug: true,
        });

        // Ensure that strategy.error is defined to avoid "this.error is not a function"
        strategy.error = jest.fn();

        // Set default mocked external function responses.
        (generateRegistrationOptions as jest.Mock).mockResolvedValue(dummyRegistrationOptions);
        (generateAuthenticationOptions as jest.Mock).mockResolvedValue(dummyAuthenticationOptions);
    });

    // --------------------------
    // Registration Flow Tests
    // --------------------------
    test("should generate registration challenge", async () => {
        const req = createRequest({ method: "GET", path: "/register" });
        const email = "test@example.com";

        const options = await strategy.registerChallenge(req, email);
        // Decode the returned challenge and compare.
        expect(decodeBase64URL(options.challenge as string)).toBe("dummy-challenge");

        // Ensure the challenge is stored for the user.
        const user = await userStore.get(email);
        expect(user).toBeDefined();
        if (user?.id) {
            const storedChallenge = await challengeStore.get(user.id);
            expect(decodeBase64URL(storedChallenge!)).toBe("dummy-challenge");
        }
    });

    test("should complete registration callback successfully", async () => {
        const email = "test@example.com";
        const user = await userStore.save({ email, passkeys: [] });
        await challengeStore.save(user.id!, dummyChallengeEncoded);

        // Mock verifyRegistrationResponse to succeed.
        (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
            verified: true,
            registrationInfo: {
                credential: {
                    publicKey: Buffer.from("dummy-public-key"),
                    id: dummyCredentialID,
                    counter: 0,
                    transports: ["internal"],
                },
            },
        });

        const req = createRequest({
            method: "POST",
            path: "/register",
            body: { credential: dummyRegistrationResponse },
        });
        const updatedUser = await strategy.registerCallback(req, email, dummyRegistrationResponse);
        expect(updatedUser.passkeys.length).toBe(1);
        expect(updatedUser.passkeys[0].id).toBe(dummyCredentialID);

        // Ensure the challenge was removed.
        const storedChallenge = await challengeStore.get(user.id!);
        expect(storedChallenge).toBeUndefined();
    });

    test("should fail registration callback if verification fails", async () => {
        const email = "test@example.com";
        const user = await userStore.save({ email, passkeys: [] });
        await challengeStore.save(user.id!, dummyChallengeEncoded);

        (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
            verified: false,
        });

        const req = createRequest({
            method: "POST",
            path: "/register",
            body: { credential: dummyRegistrationResponse },
        });
        await expect(strategy.registerCallback(req, email, dummyRegistrationResponse))
            .rejects.toThrow("Verification failed");
    });

    test("should throw error if email is missing in registration challenge", async () => {
        const req = createRequest({ method: "GET", path: "/register" });
        await expect(strategy.registerChallenge(req, ""))
            .rejects.toThrow("Email required");
    });

    // --------------------------
    // Login Flow Tests
    // --------------------------
    test("should generate authentication challenge", async () => {
        const email = "test@example.com";
        const user = await userStore.save({
            email,
            passkeys: [
                {
                    id: dummyCredentialID,
                    publicKey: new Uint8Array(), // For testing purposes.
                    counter: 0,
                    transports: ["internal"],
                },
            ],
        });
        const req = createRequest({ method: "GET", path: "/login" });

        const options = await strategy.loginChallenge(req, email);
        // Decode and compare challenge.
        expect(decodeBase64URL(options.challenge as string)).toBe("dummy-challenge");

        // Verify the challenge is stored.
        const storedChallenge = await challengeStore.get(user.id!);
        expect(decodeBase64URL(storedChallenge!)).toBe("dummy-challenge");
    });

    test("should fail authentication challenge when user does not exist", async () => {
        const req = createRequest({ method: "GET", path: "/login" });
        const email = "nonexistent@example.com";

        await expect(strategy.loginChallenge(req, email))
            .rejects.toThrow("User not found");
    });

    test("should complete login callback successfully", async () => {
        const email = "test@example.com";
        const user = await userStore.save({
            email,
            passkeys: [
                {
                    id: dummyCredentialID,
                    publicKey: Buffer.from("dummy-public-key"),
                    counter: 0,
                    transports: ["internal"],
                },
            ],
        });
        await challengeStore.save(user.id!, dummyChallengeEncoded);

        (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
            verified: true,
            authenticationInfo: {
                newCounter: 1,
            },
        });

        const req = createRequest({
            method: "POST",
            path: "/login",
            body: { credential: dummyAuthenticationResponse },
        });
        const updatedUser = await strategy.loginCallback(req, email, dummyAuthenticationResponse);
        const passkey = updatedUser.passkeys.find((p) => p.id === dummyCredentialID);
        expect(passkey).toBeDefined();
        expect(passkey!.counter).toBe(1);

        // Challenge should be removed.
        const storedChallenge = await challengeStore.get(user.id!);
        expect(storedChallenge).toBeUndefined();
    });

    test("should fail login callback when challenge is missing", async () => {
        const email = "test@example.com";
        const user = await userStore.save({
            email,
            passkeys: [
                {
                    id: dummyCredentialID,
                    publicKey: new Uint8Array(),
                    counter: 0,
                    transports: ["internal"],
                },
            ],
        });
        // No challenge stored.
        const req = createRequest({
            method: "POST",
            path: "/login",
            body: { credential: dummyAuthenticationResponse },
        });
        await expect(strategy.loginCallback(req, email, dummyAuthenticationResponse))
            .rejects.toThrow("Challenge not found");
    });

    test("should fail login callback when passkey is missing", async () => {
        const email = "test@example.com";
        const user = await userStore.save({ id: uuidv4(), email, passkeys: [] });
        await challengeStore.save(user.id!, dummyChallengeEncoded);

        const req = createRequest({
            method: "POST",
            path: "/login",
            body: { credential: dummyAuthenticationResponse },
        });
        await expect(strategy.loginCallback(req, email, dummyAuthenticationResponse))
            .rejects.toThrow("Passkey not found");
    });

    test("should fail login callback if verification fails", async () => {
        const email = "test@example.com";
        const user = await userStore.save({
            email,
            passkeys: [
                {
                    id: dummyCredentialID,
                    publicKey: Buffer.from("dummy-public-key"),
                    counter: 0,
                    transports: ["internal"],
                },
            ],
        });
        await challengeStore.save(user.id!, dummyChallengeEncoded);

        (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
            verified: false,
        });

        const req = createRequest({
            method: "POST",
            path: "/login",
            body: { credential: dummyAuthenticationResponse },
        });
        await expect(strategy.loginCallback(req, email, dummyAuthenticationResponse))
            .rejects.toThrow("Verification failed");
    });

    // --------------------------
    // Passport Strategy Integration Tests
    // --------------------------
    describe("authenticate() integration", () => {
        test("should call registerChallenge on GET /register", async () => {
            const req = createRequest({
                method: "GET",
                path: "/register",
                query: { email: "test@example.com" },
            });
            // Stub error method for authenticate
            strategy.error = jest.fn();
            const registerChallengeSpy = jest.spyOn(strategy, "registerChallenge");
            await strategy.authenticate(req);
            expect(registerChallengeSpy).toHaveBeenCalledWith(req, "test@example.com");
        });

        test("should call loginChallenge on GET /login", async () => {
            const email = "test@example.com";
            // Pre-create a user with a passkey.
            await userStore.save({
                email,
                passkeys: [
                    {
                        id: dummyCredentialID,
                        publicKey: new Uint8Array(),
                        counter: 0,
                        transports: ["internal"],
                    },
                ],
            });
            const req = createRequest({
                method: "GET",
                path: "/login",
                query: { email },
            });
            strategy.error = jest.fn();
            const loginChallengeSpy = jest.spyOn(strategy, "loginChallenge");
            await strategy.authenticate(req);
            expect(loginChallengeSpy).toHaveBeenCalledWith(req, email);
        });

        test("should call registerCallback on POST /register", async () => {
            const email = "test@example.com";
            const user = await userStore.save({ email, passkeys: [] });
            await challengeStore.save(user.id!, dummyChallengeEncoded);

            (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
                verified: true,
                registrationInfo: {
                    credential: {
                        publicKey: Buffer.from("dummy-public-key"),
                        id: dummyCredentialID,
                        counter: 0,
                        transports: ["internal"],
                    },
                },
            });

            const req = createRequest({
                method: "POST",
                path: "/register",
                body: { email, credential: dummyRegistrationResponse },
            });
            strategy.error = jest.fn();
            const registerCallbackSpy = jest.spyOn(strategy, "registerCallback");
            await strategy.authenticate(req);
            expect(registerCallbackSpy).toHaveBeenCalledWith(req, email, dummyRegistrationResponse);
        });

        test("should call loginCallback on POST /login", async () => {
            const email = "test@example.com";
            const user = await userStore.save({
                email,
                passkeys: [
                    {
                        id: dummyCredentialID,
                        publicKey: Buffer.from("dummy-public-key"),
                        counter: 0,
                        transports: ["internal"],
                    },
                ],
            });
            await challengeStore.save(user.id!, dummyChallengeEncoded);

            (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
                verified: true,
                authenticationInfo: {
                    newCounter: 2,
                },
            });

            const req = createRequest({
                method: "POST",
                path: "/login",
                body: { email, credential: dummyAuthenticationResponse },
            });
            strategy.error = jest.fn();
            const loginCallbackSpy = jest.spyOn(strategy, "loginCallback");
            await strategy.authenticate(req);
            expect(loginCallbackSpy).toHaveBeenCalledWith(req, email, dummyAuthenticationResponse);
        });

        test("should throw error if email is missing in authenticate", async () => {
            const req = createRequest({ method: "GET", path: "/login", query: {} });
            const errorSpy = jest.fn();
            strategy.error = errorSpy;
            await strategy.authenticate(req);
            expect(errorSpy).toHaveBeenCalled();
        });

        test("should throw error for unsupported HTTP methods", async () => {
            const req = createRequest({
                method: "PUT",
                path: "/login",
                body: { email: "test@example.com" },
            });
            const errorSpy = jest.fn();
            strategy.error = errorSpy;
            await strategy.authenticate(req);
            expect(errorSpy).toHaveBeenCalledWith(new Error("Unsupported HTTP method."));
        });

        test("should throw error if mode cannot be determined from path", async () => {
            const req = createRequest({
                method: "GET",
                path: "/unknown",
                query: { email: "test@example.com" },
            });
            const errorSpy = jest.fn();
            strategy.error = errorSpy;
            await strategy.authenticate(req);
            expect(errorSpy).toHaveBeenCalledWith(
                new Error("Could not infer mode. Please ensure the URL contains either register or login.")
            );
        });
    });
});