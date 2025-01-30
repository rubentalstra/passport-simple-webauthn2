// src/__tests__/strategy/registration.test.ts
jest.mock("../../strategy/challengeStore");
jest.mock("@simplewebauthn/server");

import { generateRegistration, verifyRegistration } from "passport-simple-webauthn2";
import {
    generateRegistrationOptions,
    RegistrationResponseJSON,
    verifyRegistrationResponse,
    VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../../strategy/challengeStore";
import { RegistrationUser } from "../../strategy/registration";
import type { Request } from "express";


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
            mockedGenerateRegistrationOptions.mockResolvedValueOnce({
                challenge,
                rp: { name: "Example RP", id: "example.com" },
                user: { id: userMock.id.toString(), name: userMock.name, displayName: userMock.displayName },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
                authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
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
                supportedAlgorithmIDs: [-7, -257],
            });

            expect(mockedSaveChallenge).toHaveBeenCalledWith(
                reqMock,
                Buffer.from(userMock.id).toString("base64url"),
                challenge
            );
        });
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
            const verifiedResponse: VerifiedRegistrationResponse = { verified: true };
            const challenge = "stored-challenge";

            mockedGetChallenge.mockResolvedValueOnce(challenge);
            mockedVerifyRegistrationResponse.mockResolvedValueOnce(verifiedResponse);
            mockedClearChallenge.mockResolvedValueOnce();

            const result = await verifyRegistration(reqMock as Request, userMock, response);

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, Buffer.from(userMock.id).toString("base64url"));
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: challenge,
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
            });
            expect(mockedClearChallenge).toHaveBeenCalledWith(reqMock, Buffer.from(userMock.id).toString("base64url"));
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
            mockedGetChallenge.mockResolvedValueOnce(null);

            await expect(verifyRegistration(reqMock as Request, userMock, response)).rejects.toThrow("Challenge expired or missing");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, Buffer.from(userMock.id).toString("base64url"));
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

            mockedGetChallenge.mockResolvedValueOnce(challenge);
            mockedVerifyRegistrationResponse.mockResolvedValueOnce(verifiedResponse);

            await expect(verifyRegistration(reqMock as Request, userMock, response)).rejects.toThrow("Registration verification failed");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, Buffer.from(userMock.id).toString("base64url"));
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: challenge,
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
            });
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

            mockedGetChallenge.mockResolvedValueOnce(challenge);
            mockedVerifyRegistrationResponse.mockRejectedValueOnce(new Error("Verification error"));

            await expect(verifyRegistration(reqMock as Request, userMock, response)).rejects.toThrow("Verification error");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, Buffer.from(userMock.id).toString("base64url"));
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: challenge,
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
            });
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });
    });
});