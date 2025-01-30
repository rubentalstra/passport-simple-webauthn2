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
import type { AuthUser } from "../../strategy/authentication";
import type { Request } from "express";
import { Session, SessionData } from "express-session";

// Mocked functions
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
                userId: Buffer.from([1, 2, 3, 4]).toString("base64url"),
                id: "mock-session-id",
                cookie: { path: "/", httpOnly: true, originalMaxAge: null },
                regenerate: jest.fn(),
                destroy: jest.fn(),
                reload: jest.fn(),
                resetMaxAge: jest.fn(),
                save: jest.fn(),
                touch: jest.fn(),
            } as unknown as Session & Partial<SessionData>,
        };

        authUserMock = {
            id: new Uint8Array([1, 2, 3, 4]),
            credentials: [
                {
                    id: "test-id", // Ensure this matches response.id
                    publicKey: new Uint8Array([1, 2, 3, 4]),
                    counter: 0,
                    transports: ["usb"],
                },
            ],
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

            const expectedUserId = Buffer.from(reqMock.session!.userId || "", "utf8").toString("base64");


            expect(mockedSaveChallenge).toHaveBeenCalledWith(
                reqMock,
                expectedUserId, // Buffer is passed directly
                "random-challenge"
            );
        });
    });

    describe("verifyAuthentication", () => {
        it("should verify authentication and clear challenge on success", async () => {
            const response: AuthenticationResponseJSON = {
                id: "test-id", // Matches `authUserMock.credentials`
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

            const result = await verifyAuthentication(reqMock as Request, authUserMock, response);

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, reqMock.session!.userId);
            expect(mockedVerifyAuthenticationResponse).toHaveBeenCalledWith({
                response,
                expectedChallenge: "stored-challenge",
                expectedOrigin: "https://example.com",
                expectedRPID: "example.com",
                credential: authUserMock.credentials[0], // Ensure credential is passed
                requireUserVerification: true,
            });

            expect(mockedClearChallenge).toHaveBeenCalledWith(reqMock, reqMock.session!.userId);
            expect(result).toBe(verification);
        });

        it("should throw an error if credential is not found", async () => {
            const response: AuthenticationResponseJSON = {
                id: "nonexistent-credential-id", // Does NOT match authUserMock.credentials
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

            await expect(verifyAuthentication(reqMock as Request, authUserMock, response)).rejects.toThrow("Credential not found");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, reqMock.session!.userId);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });
    });
});