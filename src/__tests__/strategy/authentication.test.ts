jest.mock("../../strategy/challengeStore");
jest.mock("@simplewebauthn/server");

import { generateAuthentication, verifyAuthentication } from "../../strategy/authentication";
import {
    AuthenticationResponseJSON,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
    VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../../strategy/challengeStore";
import type { Request } from "express";

// Mocked functions
const mockedGenerateAuthenticationOptions = generateAuthenticationOptions as jest.MockedFunction<typeof generateAuthenticationOptions>;
const mockedVerifyAuthenticationResponse = verifyAuthenticationResponse as jest.MockedFunction<typeof verifyAuthenticationResponse>;
const mockedSaveChallenge = saveChallenge as jest.MockedFunction<typeof saveChallenge>;
const mockedGetChallenge = getChallenge as jest.MockedFunction<typeof getChallenge>;
const mockedClearChallenge = clearChallenge as jest.MockedFunction<typeof clearChallenge>;

describe("Authentication Utility Functions", () => {
    let reqMock: Partial<Request>;
    let userMock: { id: string; credentials: any[] };

    beforeEach(() => {
        reqMock = {
            user: {
                id: "user123",
                credentials: [
                    {
                        id: "test-id",
                        publicKey: new Uint8Array([1, 2, 3, 4]),
                        counter: 0,
                        transports: ["usb"],
                    },
                ],
            },
        } as Partial<Request>;

        userMock = reqMock.user as { id: string; credentials: any[] };
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
                allowCredentials: [
                    {
                        id: userMock.credentials[0].id,
                        transports: userMock.credentials[0].transports || [],
                    },
                ],
                timeout: 60000,
                userVerification: "preferred",
            });

            expect(mockedSaveChallenge).toHaveBeenCalledWith(
                reqMock,
                userMock.id,
                "random-challenge"
            );
        });

        it("should throw an error if req.user is missing", async () => {
            reqMock.user = undefined;

            await expect(generateAuthentication(reqMock as Request)).rejects.toThrow("User not authenticated");
            expect(mockedGenerateAuthenticationOptions).not.toHaveBeenCalled();
            expect(mockedSaveChallenge).not.toHaveBeenCalled();
        });
    });

    describe("verifyAuthentication", () => {
        it("should verify authentication and clear challenge on success", async () => {
            const response: AuthenticationResponseJSON = {
                id: "test-id", // Matches `userMock.credentials`
                rawId: "test-raw-id",
                type: "public-key",
                response: {
                    authenticatorData: "test-authenticator-data",
                    clientDataJSON: "test-client-data-json",
                    signature: "test-signature",
                },
                clientExtensionResults: {},
            };

            const verification: VerifiedAuthenticationResponse = {
                verified: true,
                authenticationInfo: {
                    credentialID: "test-id",
                    newCounter: 0,
                    userVerified: true,
                    credentialDeviceType: "singleDevice",
                    credentialBackedUp: false,
                    origin: "https://example.com",
                    rpID: "example.com",
                    authenticatorExtensionResults: {},
                },
            };

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");
            mockedVerifyAuthenticationResponse.mockResolvedValueOnce(verification);
            mockedClearChallenge.mockResolvedValueOnce();

            const result = await verifyAuthentication(reqMock as Request, response);

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userMock.id);
            expect(mockedVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: "stored-challenge",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                credential: userMock.credentials[0], // Ensure correct credential is passed
                requireUserVerification: true,
            });

            expect(mockedClearChallenge).toHaveBeenCalledWith(reqMock, userMock.id);
            expect(result).toBe(verification);
        });

        it("should throw an error if credential is not found", async () => {
            const response: AuthenticationResponseJSON = {
                id: "nonexistent-credential-id", // Does NOT match userMock.credentials
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

            await expect(verifyAuthentication(reqMock as Request, response)).rejects.toThrow("Credential not found");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userMock.id);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if req.user is missing", async () => {
            reqMock.user = undefined;

            await expect(verifyAuthentication(reqMock as Request, {} as AuthenticationResponseJSON)).rejects.toThrow(
                "User not authenticated"
            );

            expect(mockedGetChallenge).not.toHaveBeenCalled();
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });
    });
});