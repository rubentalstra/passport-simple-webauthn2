// src/__tests__/strategy/authentication.test.ts

jest.mock("../../strategy/challengeStore");
jest.mock("@simplewebauthn/server");

import { generateAuthentication, verifyAuthentication } from "passport-simple-webauthn2";
import {
    AuthenticationResponseJSON,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../../strategy/challengeStore";
import type { AuthUser } from "../../strategy/authentication";
import type { Request } from "express";
import {Session, SessionData} from "express-session";


const mockedGenerateAuthenticationOptions = generateAuthenticationOptions as jest.MockedFunction<typeof generateAuthenticationOptions>;
const mockedVerifyAuthenticationResponse = verifyAuthenticationResponse as jest.MockedFunction<typeof verifyAuthenticationResponse>;
const mockedSaveChallenge = saveChallenge as jest.MockedFunction<typeof saveChallenge>;
const mockedGetChallenge = getChallenge as jest.MockedFunction<typeof getChallenge>;
const mockedClearChallenge = clearChallenge as jest.MockedFunction<typeof clearChallenge>;

describe("Authentication Utility Functions", () => {
    let reqMock: Partial<Request>;
    let authUserMock: AuthUser;

    beforeEach(() => {
        reqMock = {
            session: {
                userId: Buffer.from(new Uint8Array([1, 2, 3, 4])).toString("base64url"),
                id: "mock-session-id",
                cookie: {
                    path: "/",
                    httpOnly: true,
                    originalMaxAge: null
                },
                regenerate: jest.fn(),
                destroy: jest.fn(),
                reload: jest.fn(),
                resetMaxAge: jest.fn(),
                save: jest.fn(),
                touch: jest.fn(),
            },
        };
        authUserMock = {
            id: new Uint8Array([1, 2, 3, 4]),
            credentials: [],
        };
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe("generateAuthentication", () => {
        it("should generate authentication options and save challenge", async () => {
            const challenge = "random-challenge";
            mockedGenerateAuthenticationOptions.mockResolvedValueOnce({
                challenge,
                allowCredentials: [],
                userVerification: "preferred",
            });

            await generateAuthentication(reqMock as Request);

            expect(mockedGenerateAuthenticationOptions).toHaveBeenCalledWith({
                rpID: "example.com",
            });

            expect(mockedSaveChallenge).toHaveBeenCalledWith(
                reqMock,
                Buffer.from(authUserMock.id).toString("base64url"),
                challenge
            );
        });

        it("should throw an error if user is not authenticated", async () => {
            reqMock.session = {} as Session & Partial<SessionData>;

            await expect(generateAuthentication(reqMock as Request)).rejects.toThrow("User not authenticated");
            expect(mockedGenerateAuthenticationOptions).not.toHaveBeenCalled();
            expect(mockedSaveChallenge).not.toHaveBeenCalled();
        });
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
                    // 'userHandle' is optional; omit or provide a valid string
                },
                clientExtensionResults: {},
            };
            const verification: VerifiedAuthenticationResponse = {
                verified: true,
                authenticationInfo: {
                    credentialID: "test-credential-id",
                    newCounter: 0,
                    userVerified: true,
                    credentialDeviceType: "singleDevice",
                    credentialBackedUp: false,
                    origin: "https://example.com",
                    rpID: "example.com",
                    authenticatorExtensionResults: {},
                }
            };
            const userIdBase64 = Buffer.from(authUserMock.id).toString("base64url");

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            mockedVerifyAuthenticationResponse.mockResolvedValueOnce(verification);
            mockedClearChallenge.mockResolvedValueOnce();

            const result = await verifyAuthentication(reqMock as Request, authUserMock, response);

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(mockedVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: "stored-challenge",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                credential: undefined, // Assuming no specific credential is provided in authUserMock
                requireUserVerification: true,
            });
            expect(mockedClearChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(result).toBe(verification);
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
                    // 'userHandle' is optional; omit or provide a valid string
                },
                clientExtensionResults: {},
            };
            const userIdBase64 = Buffer.from(authUserMock.id).toString("base64url");

            mockedGetChallenge.mockResolvedValueOnce(null);

            await expect(verifyAuthentication(reqMock as Request, authUserMock, response)).rejects.toThrow("Challenge expired or missing");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if credential is not found", async () => {
            const response: AuthenticationResponseJSON = {
                id: "nonexistent-credential-id",
                rawId: "nonexistent-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "nonexistent-authenticator-data",
                    clientDataJSON: "nonexistent-client-data-json",
                    signature: "nonexistent-signature",
                    // 'userHandle' is optional; omit or provide a valid string
                },
                clientExtensionResults: {},
            };
            const userIdBase64 = Buffer.from(authUserMock.id).toString("base64url");

            authUserMock.credentials = [
                {
                    id: "existing-credential-id",
                    publicKey: new Uint8Array(),
                    counter: 0,
                    transports: [],
                },
            ];

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");

            await expect(verifyAuthentication(reqMock as Request, authUserMock, response)).rejects.toThrow("Credential not found");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if verification fails", async () => {
            const response: AuthenticationResponseJSON = {
                id: "test-id",
                rawId: "test-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "test-authenticator-data",
                    clientDataJSON: "test-client-data-json",
                    signature: "test-signature",
                    // 'userHandle' is optional; omit or provide a valid string
                },
                clientExtensionResults: {},
            };
            const verification: VerifiedAuthenticationResponse = {
                verified: false,
                authenticationInfo: {
                    credentialID: "test-credential-id",
                    newCounter: 0,
                    userVerified: false,
                    credentialDeviceType: "singleDevice",
                    credentialBackedUp: false,
                    origin: "https://example.com",
                    rpID: "example.com",
                    authenticatorExtensionResults: {},
                }
            };
            const userIdBase64 = Buffer.from(authUserMock.id).toString("base64url");

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            mockedVerifyAuthenticationResponse.mockResolvedValueOnce(verification);

            await expect(verifyAuthentication(reqMock as Request, authUserMock, response)).rejects.toThrow("Authentication failed");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(mockedVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: "stored-challenge",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                credential: undefined, // Assuming no specific credential is provided in authUserMock
                requireUserVerification: true,
            });
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if verifyAuthenticationResponse throws", async () => {
            const response: AuthenticationResponseJSON = {
                id: "test-id",
                rawId: "test-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "test-authenticator-data",
                    clientDataJSON: "test-client-data-json",
                    signature: "test-signature",
                    // 'userHandle' is optional; omit or provide a valid string
                },
                clientExtensionResults: {},
            };
            const userIdBase64 = Buffer.from(authUserMock.id).toString("base64url");

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            mockedVerifyAuthenticationResponse.mockRejectedValueOnce(new Error("Verification error"));

            await expect(verifyAuthentication(reqMock as Request, authUserMock, response)).rejects.toThrow("Verification error");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(mockedVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: "stored-challenge",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                credential: undefined,
                requireUserVerification: true,
            });
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });
    });
});