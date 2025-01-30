jest.mock("../../strategy/challengeStore");
jest.mock("@simplewebauthn/server");

import { generateRegistration, verifyRegistration } from "../../strategy/verifyRegistration";
import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    RegistrationResponseJSON,
    VerifiedRegistrationResponse,
    PublicKeyCredentialCreationOptionsJSON,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../../strategy/challengeStore";
import type { UserModel } from "../../models/types";

// Mocked functions
const mockedGenerateRegistrationOptions = generateRegistrationOptions as jest.MockedFunction<typeof generateRegistrationOptions>;
const mockedVerifyRegistrationResponse = verifyRegistrationResponse as jest.MockedFunction<typeof verifyRegistrationResponse>;
const mockedSaveChallenge = saveChallenge as jest.MockedFunction<typeof saveChallenge>;
const mockedGetChallenge = getChallenge as jest.MockedFunction<typeof getChallenge>;
const mockedClearChallenge = clearChallenge as jest.MockedFunction<typeof clearChallenge>;

// Mock database functions
const findUserByWebAuthnID = jest.fn();
const registerPasskey = jest.fn();

describe("Registration Utility Functions", () => {
    let userMock: UserModel;

    beforeEach(() => {
        userMock = {
            id: "user123",
            username: "testuser",
            displayName: "Test User",
        } as UserModel;
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe("generateRegistration", () => {
        it("should generate registration options and save challenge", async () => {
            const challenge = "random-challenge";

            const expectedOptions: PublicKeyCredentialCreationOptionsJSON = {
                challenge,
                rp: { name: process.env.RP_NAME || "Example RP", id: process.env.RP_ID || "example.com" },
                user: {
                    id: Buffer.from(userMock.id).toString("base64url"),
                    name: userMock.username,
                    displayName: 'Test User',
                },
                pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
                authenticatorSelection: {
                    residentKey: "preferred",
                    userVerification: "preferred",
                    authenticatorAttachment: "platform",
                },
                attestation: "none",
            };

            mockedGenerateRegistrationOptions.mockResolvedValueOnce(expectedOptions);

            const result = await generateRegistration(userMock);

            expect(mockedGenerateRegistrationOptions).toHaveBeenCalledWith(
                expect.objectContaining({
                    rpName: process.env.RP_NAME || "Example RP",
                    rpID: process.env.RP_ID || "example.com",
                    userID: expect.any(Buffer),
                    userName: userMock.username,
                })
            );

            expect(mockedSaveChallenge).toHaveBeenCalledWith(userMock.id, challenge);
            expect(result).toEqual(expectedOptions);
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

            const verificationResult: VerifiedRegistrationResponse = {
                verified: true,
                registrationInfo: {
                    fmt: "packed",
                    aaguid: "550e8400-e29b-41d4-a716-446655440000",
                    credential: {
                        id: "test-id",
                        publicKey: new Uint8Array([1, 2, 3, 4]),
                        counter: 0,
                        transports: ["usb"],
                    },
                    credentialType: "public-key",
                    attestationObject: new Uint8Array([5, 6, 7, 8]),
                    userVerified: true,
                    credentialDeviceType: "singleDevice",
                    credentialBackedUp: false,
                    origin: `https://${process.env.RP_ID || "example.com"}`,
                },
            };

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            mockedVerifyRegistrationResponse.mockResolvedValueOnce(verificationResult);
            mockedClearChallenge.mockResolvedValueOnce();
            findUserByWebAuthnID.mockResolvedValueOnce(userMock);

            const result = await verifyRegistration(response, findUserByWebAuthnID, registerPasskey);

            expect(mockedGetChallenge).toHaveBeenCalledWith(response.id);
            expect(mockedVerifyRegistrationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: "stored-challenge",
                expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
                expectedRPID: process.env.RP_ID || "example.com",
                requireUserVerification: true,
            });

            expect(registerPasskey).toHaveBeenCalledWith(
                expect.objectContaining({
                    id: "test-id",
                    webauthnUserID: "user123",
                    user: userMock,
                })
            );

            expect(mockedClearChallenge).toHaveBeenCalledWith(response.id);
            expect(result).toBe(verificationResult);
        });

        it("should throw an error if userHandle is missing", async () => {
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

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");

            await expect(verifyRegistration(response, findUserByWebAuthnID, registerPasskey)).rejects.toThrow(
                "User handle (WebAuthn user ID) missing in registration response"
            );

            expect(mockedGetChallenge).toHaveBeenCalledWith(response.id);
            expect(mockedVerifyRegistrationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if user is not found", async () => {
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

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            findUserByWebAuthnID.mockResolvedValueOnce(null);

            await expect(verifyRegistration(response, findUserByWebAuthnID, registerPasskey)).rejects.toThrow(
                "User not found"
            );

            expect(mockedGetChallenge).toHaveBeenCalledWith(response.id);
            expect(mockedVerifyRegistrationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });
    });
});