jest.mock("../../strategy/challengeStore");
jest.mock("@simplewebauthn/server");

import { generateRegistration, verifyRegistration } from "../../strategy/registration";
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../../strategy/challengeStore";
import type { Request } from "express";

const mockedGenerateRegistrationOptions = generateRegistrationOptions as jest.MockedFunction<typeof generateRegistrationOptions>;
const mockedVerifyRegistrationResponse = verifyRegistrationResponse as jest.MockedFunction<typeof verifyRegistrationResponse>;
const mockedSaveChallenge = saveChallenge as jest.MockedFunction<typeof saveChallenge>;
const mockedGetChallenge = getChallenge as jest.MockedFunction<typeof getChallenge>;
const mockedClearChallenge = clearChallenge as jest.MockedFunction<typeof clearChallenge>;

describe("Registration Utility Functions", () => {
    let reqMock: Partial<Request>;
    let userMock: { id: string; name: string; displayName: string; credentials: any[] };

    beforeEach(() => {
        reqMock = {};
        userMock = {
            id: "user123",
            name: "testuser",
            displayName: "Test User",
            credentials: [],
        };
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe("generateRegistration", () => {
        it("should generate registration options and save challenge", async () => {
            reqMock.user = userMock;
            const challenge = "random-challenge";

            mockedGenerateRegistrationOptions.mockResolvedValueOnce({
                challenge,
                rp: { name: "Example RP", id: "example.com" },
                user: {
                    id: userMock.id,
                    name: userMock.name,
                    displayName: userMock.displayName,
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -8 },
                    { type: "public-key", alg: -7 },
                    { type: "public-key", alg: -257 },
                ],
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "preferred",
                },
                attestation: "direct",
            });

            await generateRegistration(reqMock as Request);

            expect(mockedGenerateRegistrationOptions).toHaveBeenCalledWith({
                rpName: "Example RP",
                rpID: "example.com",
                userID: Buffer.from(userMock.id), // ✅ Convert to Buffer
                userName: userMock.name,
                userDisplayName: userMock.displayName, // ✅ Now included
                attestationType: "direct",
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "preferred",
                },
                supportedAlgorithmIDs: [-8, -7, -257],
                preferredAuthenticatorType: "securityKey", // ✅ Now included
            });

            expect(mockedSaveChallenge).toHaveBeenCalledWith(reqMock, userMock.id, challenge);
        });
    });

    describe("verifyRegistration", () => {
        it("should verify registration and clear challenge on success", async () => {
            reqMock.user = userMock;
            const response: RegistrationResponseJSON = {
                id: "test-id",
                rawId: "test-raw-id", // Ensure rawId is included
                response: {
                    attestationObject: "test-attestation-object",
                    clientDataJSON: "test-client-data-json",
                },
                clientExtensionResults: {}, // Required field
                type: "public-key", // Required field
            };
            const verifiedResponse = { verified: true };
            const challenge = "stored-challenge";

            mockedGetChallenge.mockResolvedValueOnce(challenge);
            mockedVerifyRegistrationResponse.mockResolvedValueOnce(verifiedResponse);
            mockedClearChallenge.mockResolvedValueOnce();

            const result = await verifyRegistration(reqMock as Request, response);

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userMock.id);
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: challenge,
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
            });

            expect(mockedClearChallenge).toHaveBeenCalledWith(reqMock, userMock.id);
            expect(result).toBe(verifiedResponse);
        });

        it("should throw an error if challenge is missing", async () => {
            reqMock.user = userMock;
            mockedGetChallenge.mockResolvedValueOnce(null);

            const response: RegistrationResponseJSON = {
                id: "test-id",
                rawId: "test-raw-id",
                response: {
                    attestationObject: "test-attestation-object",
                    clientDataJSON: "test-client-data-json",
                },
                clientExtensionResults: {},
                type: "public-key",
            };

            await expect(verifyRegistration(reqMock as Request, response)).rejects.toThrow("Challenge expired or missing");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userMock.id);
        });

        it("should throw an error when given an empty response object", async () => {
            reqMock.user = userMock;

            const invalidResponse = {} as RegistrationResponseJSON; // Properly cast to expected type

            await expect(verifyRegistration(reqMock as Request, invalidResponse)).rejects.toThrowError();
        });
    });
});