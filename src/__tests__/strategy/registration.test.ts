// src/__tests__/strategy/registration.test.ts

// Mock the required modules
jest.mock("../../strategy/challengeStore");
jest.mock("@simplewebauthn/server");

import { generateRegistration, verifyRegistration } from "../../strategy/registration";
import {
    generateRegistrationOptions,
    RegistrationResponseJSON,
    verifyRegistrationResponse,
    VerifiedRegistrationResponse,
    PublicKeyCredentialCreationOptionsJSON,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../../strategy/challengeStore";
import { RegistrationUser } from "../../strategy/registration";
import type { Request } from "express";

import { Buffer } from "buffer"; // Ensure Buffer is available

// Type assertions for mocked functions
const mockedGenerateRegistrationOptions = generateRegistrationOptions as jest.MockedFunction<typeof generateRegistrationOptions>;
const mockedVerifyRegistrationResponse = verifyRegistrationResponse as jest.MockedFunction<typeof verifyRegistrationResponse>;
const mockedSaveChallenge = saveChallenge as jest.MockedFunction<typeof saveChallenge>;
const mockedGetChallenge = getChallenge as jest.MockedFunction<typeof getChallenge>;
const mockedClearChallenge = clearChallenge as jest.MockedFunction<typeof clearChallenge>;

describe("Registration Utility Functions", () => {
    let reqMock: Partial<Request>;
    let userMock: RegistrationUser;

    beforeEach(() => {
        reqMock = {};
        userMock = {
            id: new Uint8Array([1, 2, 3, 4]),
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
            const challenge = "random-challenge";
            const encodedUserId = Buffer.from(userMock.id).toString("base64url");

            // Mock generateRegistrationOptions response
            mockedGenerateRegistrationOptions.mockResolvedValueOnce({
                challenge,
                rp: { name: "Example RP", id: "example.com" },
                user: {
                    id: encodedUserId,
                    name: userMock.name,
                    displayName: userMock.displayName,
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -8 },
                    { type: "public-key", alg: -7 },
                    { type: "public-key", alg: -257 }
                ],
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "preferred",
                },
                attestation: "direct",
            });


            await generateRegistration(reqMock as Request, userMock);

            expect(mockedGenerateRegistrationOptions).toHaveBeenCalledWith({
                rpName: "Example RP",
                rpID: "example.com",
                userID: userMock.id,
                userName: userMock.name,
                attestationType: "direct",
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "preferred",
                },
                supportedAlgorithmIDs: [-8, -7, -257],
            });

            expect(mockedSaveChallenge).toHaveBeenCalledWith(
                reqMock,
                encodedUserId,
                challenge
            );
        });
    });

        it("should handle generateRegistrationOptions failure", async () => {
            const error = new Error("Failed to generate registration options");
            mockedGenerateRegistrationOptions.mockRejectedValueOnce(error);
            const encodedUserId = Buffer.from(userMock.id).toString("base64url");

            await expect(generateRegistration(reqMock as Request, userMock)).rejects.toThrow("Failed to generate registration options");

            expect(mockedGenerateRegistrationOptions).toHaveBeenCalledWith({
                rpName: "Example RP",
                rpID: "example.com",
                userID: userMock.id,
                userName: userMock.name,
                attestationType: "direct",
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "preferred",
                },
                supportedAlgorithmIDs: [-8, -7, -257],
            });

            // Ensure saveChallenge is not called on failure
            expect(mockedSaveChallenge).not.toHaveBeenCalled();
        });

    describe("verifyRegistration", () => {
        it("should verify registration and clear challenge on success", async () => {
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
            const verifiedResponse: VerifiedRegistrationResponse = {
                verified: true,
            };
            const challenge = "stored-challenge";
            const encodedUserId = Buffer.from(userMock.id).toString("base64url");

            // Mock the challenge retrieval
            mockedGetChallenge.mockResolvedValueOnce(challenge);

            // Mock the verification response
            mockedVerifyRegistrationResponse.mockResolvedValueOnce(verifiedResponse);

            // Mock clearing the challenge
            mockedClearChallenge.mockResolvedValueOnce();

            // Call the function under test
            const result = await verifyRegistration(reqMock as Request, userMock, response);

            // Expect getChallenge to be called with correctly encoded user ID
            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, encodedUserId);

            // Expect verifyRegistrationResponse to be called with correct parameters
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: challenge,
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
            });

            // Expect clearChallenge to be called upon successful verification
            expect(mockedClearChallenge).toHaveBeenCalledWith(reqMock, encodedUserId);

            // The result should be the verified response
            expect(result).toBe(verifiedResponse);
        });

        it("should throw an error if challenge is missing", async () => {
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
            const encodedUserId = Buffer.from(userMock.id).toString("base64url");

            // Mock getChallenge to return null, simulating a missing challenge
            mockedGetChallenge.mockResolvedValueOnce(null);

            // Expect verifyRegistration to throw an error
            await expect(verifyRegistration(reqMock as Request, userMock, response)).rejects.toThrow("Challenge expired or missing");

            // Expect getChallenge to be called with correctly encoded user ID
            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, encodedUserId);

            // Ensure verifyRegistrationResponse and clearChallenge are not called
            expect(mockedVerifyRegistrationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if verification fails", async () => {
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
            const verifiedResponse: VerifiedRegistrationResponse = { verified: false };
            const challenge = "stored-challenge";
            const encodedUserId = Buffer.from(userMock.id).toString("base64url");

            // Mock the challenge retrieval
            mockedGetChallenge.mockResolvedValueOnce(challenge);

            // Mock the verification response to indicate failure
            mockedVerifyRegistrationResponse.mockResolvedValueOnce(verifiedResponse);

            // Call the function under test and expect it to throw
            await expect(verifyRegistration(reqMock as Request, userMock, response)).rejects.toThrow("Registration verification failed");

            // Expect getChallenge to be called with correctly encoded user ID
            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, encodedUserId);

            // Expect verifyRegistrationResponse to be called with correct parameters
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: challenge,
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
            });

            // Ensure clearChallenge is not called since verification failed
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if verifyRegistrationResponse throws", async () => {
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
            const challenge = "stored-challenge";
            const encodedUserId = Buffer.from(userMock.id).toString("base64url");

            // Mock the challenge retrieval
            mockedGetChallenge.mockResolvedValueOnce(challenge);

            // Mock verifyRegistrationResponse to throw an error
            mockedVerifyRegistrationResponse.mockRejectedValueOnce(new Error("Verification error"));

            // Call the function under test and expect it to throw
            await expect(verifyRegistration(reqMock as Request, userMock, response)).rejects.toThrow("Verification error");

            // Expect getChallenge to be called with correctly encoded user ID
            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, encodedUserId);

            // Expect verifyRegistrationResponse to be called with correct parameters
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: challenge,
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
            });

            // Ensure clearChallenge is not called since verification failed
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });
    });
});