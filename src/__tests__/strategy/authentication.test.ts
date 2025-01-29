import { generateAuthentication, verifyAuthentication } from "../../strategy/authentication";
import { generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "../../strategy/challengeStore";
import type { AuthUser, VerifiedAuthenticationResponse } from "passport-simple-webauthn2";
import type { Request } from "express";

jest.mock("@simplewebauthn/server");
jest.mock("../../strategy/challengeStore");

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
                userId: new Uint8Array([1, 2, 3, 4]).toString(), // Simulate base64url-encoded userId
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
                Buffer.from(reqMock.session!.userId!, "base64url").toString("base64url"),
                challenge
            );
        });

        it("should throw an error if user is not authenticated", async () => {
            reqMock.session = {}; // No userId

            await expect(generateAuthentication(reqMock as Request)).rejects.toThrow("User not authenticated");
            expect(mockedGenerateAuthenticationOptions).not.toHaveBeenCalled();
            expect(mockedSaveChallenge).not.toHaveBeenCalled();
        });
    });

    describe("verifyAuthentication", () => {
        it("should verify authentication and clear challenge on success", async () => {
            const response = { /* mock AuthenticationResponseJSON */ };
            const verification: VerifiedAuthenticationResponse = { verified: true };
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
            const response = { /* mock AuthenticationResponseJSON */ };
            const userIdBase64 = Buffer.from(authUserMock.id).toString("base64url");

            mockedGetChallenge.mockResolvedValueOnce(null);

            await expect(verifyAuthentication(reqMock as Request, authUserMock, response)).rejects.toThrow("Challenge expired or missing");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if credential is not found", async () => {
            const response = { id: "nonexistent-credential-id" };
            const verification: VerifiedAuthenticationResponse = { verified: true };
            const userIdBase64 = Buffer.from(authUserMock.id).toString("base64url");

            authUserMock.credentials = [
                { id: "existing-credential-id", publicKey: new Uint8Array(), user: { id: "1", username: "testuser" }, webauthnUserID: "user-id", counter: 0, deviceType: "usb", backedUp: false },
            ];

            mockedGetChallenge.mockResolvedValueOnce("stored-challenge");

            await expect(verifyAuthentication(reqMock as Request, authUserMock, response)).rejects.toThrow("Credential not found");

            expect(mockedGetChallenge).toHaveBeenCalledWith(reqMock, userIdBase64);
            expect(mockedVerifyAuthenticationResponse).not.toHaveBeenCalled();
            expect(mockedClearChallenge).not.toHaveBeenCalled();
        });

        it("should throw an error if verification fails", async () => {
            const response = { /* mock AuthenticationResponseJSON */ };
            const verification: VerifiedAuthenticationResponse = { verified: false };
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
            const response = { /* mock AuthenticationResponseJSON */ };
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