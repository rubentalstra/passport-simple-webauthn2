jest.mock("../../strategy/challengeStore");
jest.mock("@simplewebauthn/server");

import { verifyAuthentication } from "../../strategy/verifyAuthentication";
import {
    AuthenticationResponseJSON,
    verifyAuthenticationResponse,
    VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import { getChallenge, clearChallenge } from "../../strategy/challengeStore";
import type { Request } from "express";
import type { UserModel, Passkey } from "../../models/types";

// Mocked functions
const mockedVerifyAuthenticationResponse = verifyAuthenticationResponse as jest.MockedFunction<typeof verifyAuthenticationResponse>;
const mockedGetChallenge = getChallenge as jest.MockedFunction<typeof getChallenge>;
const mockedClearChallenge = clearChallenge as jest.MockedFunction<typeof clearChallenge>;

// Mock function for updating passkey counter
const updatePasskeyCounter = jest.fn().mockResolvedValue(undefined);

describe("Authentication Utility Functions", () => {
    let reqMock: Partial<Request>;
    let userMock: UserModel;

    beforeEach(() => {
        userMock = {
            id: "user123",
            username: "testuser",
        } as UserModel;

        reqMock = {
            user: userMock,
        } as Partial<Request>;
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe("verifyAuthentication", () => {
        it("should verify authentication and clear challenge on success", async () => {
            const response: AuthenticationResponseJSON = {
                id: "test-id",
                rawId: "test-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "test-authenticator-data",
                    clientDataJSON: "test-client-data-json",
                    signature: "test-signature",
                },
                clientExtensionResults: {},
            };

            const passkey: Passkey = {
                id: "test-id",
                publicKey: new Uint8Array([1, 2, 3, 4]),
                counter: 0,
                transports: ["usb"],
                user: userMock,
                webauthnUserID: userMock.id,
                deviceType: "singleDevice",
                backedUp: false,
            };

            const verification: VerifiedAuthenticationResponse = {
                verified: true,
                authenticationInfo: {
                    credentialID: "test-id",
                    newCounter: 10,
                    userVerified: true,
                    credentialDeviceType: "singleDevice",
                    credentialBackedUp: false,
                    origin: `https://${process.env.RP_ID || "example.com"}`,
                    rpID: process.env.RP_ID || "example.com",
                    authenticatorExtensionResults: {},
                },
            };

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            mockedVerifyAuthenticationResponse.mockResolvedValueOnce(verification);
            mockedClearChallenge.mockResolvedValueOnce();

            const result = await verifyAuthentication(reqMock as Request, response, async () => passkey, updatePasskeyCounter);

            expect(mockedGetChallenge).toHaveBeenCalledWith(userMock.id);
            expect(mockedVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: "stored-challenge",
                expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
                expectedRPID: process.env.RP_ID || "example.com",
                credential: {
                    id: passkey.id,
                    publicKey: passkey.publicKey,
                    counter: passkey.counter,
                    transports: passkey.transports,
                },
                requireUserVerification: true,
            });

            expect(updatePasskeyCounter).toHaveBeenCalledWith("test-id", 10);

            expect(mockedClearChallenge).toHaveBeenCalledWith(userMock.id);
            expect(result).toBe(verification);
        });

        it("should throw an error if credential is not found", async () => {
            const response: AuthenticationResponseJSON = {
                id: "nonexistent-credential-id",
                rawId: "nonexistent-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "test-authenticator-data",
                    clientDataJSON: "test-client-data-json",
                    signature: "test-signature",
                },
                clientExtensionResults: {},
            };

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");

            await expect(verifyAuthentication(reqMock as Request, response, async () => null, updatePasskeyCounter))
                .rejects.toThrow("Credential not found");

            expect(mockedGetChallenge).toHaveBeenCalledWith(userMock.id);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if challenge is missing", async () => {
            const response: AuthenticationResponseJSON = {
                id: "test-id",
                rawId: "test-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "test-authenticator-data",
                    clientDataJSON: "test-client-data-json",
                    signature: "test-signature",
                },
                clientExtensionResults: {},
            };

            mockedGetChallenge.mockResolvedValueOnce(null);

            await expect(verifyAuthentication(reqMock as Request, response, async () => null, updatePasskeyCounter))
                .rejects.toThrow("Challenge expired or missing");

            expect(mockedGetChallenge).toHaveBeenCalledWith(userMock.id);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if authentication fails", async () => {
            const response: AuthenticationResponseJSON = {
                id: "test-id",
                rawId: "test-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "test-authenticator-data",
                    clientDataJSON: "test-client-data-json",
                    signature: "test-signature",
                },
                clientExtensionResults: {},
            };

            const passkey: Passkey = {
                id: "test-id",
                publicKey: new Uint8Array([1, 2, 3, 4]),
                counter: 0,
                transports: ["usb"],
                user: userMock,
                webauthnUserID: userMock.id,
                deviceType: "singleDevice",
                backedUp: false,
            };

            const verification: VerifiedAuthenticationResponse = {
                verified: false,
                authenticationInfo: {
                    credentialID: "test-id",
                    newCounter: 10,
                    userVerified: true,
                    credentialDeviceType: "singleDevice",
                    credentialBackedUp: false,
                    origin: `https://${process.env.RP_ID || "example.com"}`,
                    rpID: process.env.RP_ID || "example.com",
                    authenticatorExtensionResults: {},
                },
            };

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            mockedVerifyAuthenticationResponse.mockResolvedValueOnce(verification);

            await expect(verifyAuthentication(reqMock as Request, response, async () => passkey, updatePasskeyCounter))
                .rejects.toThrow("Authentication failed");

            expect(mockedGetChallenge).toHaveBeenCalledWith(userMock.id);
            expect(mockedVerifyAuthenticationResponse).toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if req.user is missing", async () => {
            reqMock.user = undefined;

            await expect(verifyAuthentication(reqMock as Request, {} as AuthenticationResponseJSON, async () => null, updatePasskeyCounter))
                .rejects.toThrow("User not authenticated");

            expect(mockedGetChallenge).not.toHaveBeenCalled();
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });
    });
});