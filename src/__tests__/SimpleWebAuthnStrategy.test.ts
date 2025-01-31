import { SimpleWebAuthnStrategy } from "../strategy/SimpleWebAuthnStrategy";
import { verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import type { Request } from "express";
import type { SimpleWebAuthnStrategyOptions, Passkey } from "../types";

// Mocking @simplewebauthn/server functions
jest.mock("@simplewebauthn/server", () => ({
    verifyAuthenticationResponse: jest.fn(),
    verifyRegistrationResponse: jest.fn(),
}));

describe("SimpleWebAuthnStrategy", () => {
    let strategy: SimpleWebAuthnStrategy;
    let options: SimpleWebAuthnStrategyOptions;

    beforeEach(() => {
        // Clear mocks instead of resetting them
        jest.clearAllMocks();

        // Define mock functions for strategy options
        options = {
            findPasskeyByCredentialID: jest.fn(),
            updatePasskeyCounter: jest.fn(),
            registerPasskey: jest.fn(),
        };

        // Instantiate the strategy
        strategy = new SimpleWebAuthnStrategy(options);

        // Mock inherited methods from Passport's Strategy
        Object.assign(strategy, {
            success: jest.fn(),
            fail: jest.fn(),
            error: jest.fn(),
        });
    });

    describe("handleAuthentication", () => {
        it("should authenticate successfully with valid credentials", async () => {
            // Arrange
            const mockUserID = "user123";
            const mockCredentialID = "credential123";
            const mockPublicKey = new Uint8Array([1, 2, 3]);
            const mockNewCounter = 100;

            const mockPasskey: Passkey = {
                id: mockCredentialID,
                publicKey: mockPublicKey,
                userID: mockUserID,
                webauthnUserID: "webauthnUser123",
                counter: 99,
                transports: ["usb"],
            };

            // Mock findPasskeyByCredentialID
            (options.findPasskeyByCredentialID as jest.Mock).mockResolvedValue(mockPasskey);

            // Mock verifyAuthenticationResponse
            (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({
                verified: true,
                authenticationInfo: {
                    newCounter: mockNewCounter,
                },
            });

            // Mock request object
            const req = {
                path: "/login-callback",
                body: {
                    response: { id: mockCredentialID },
                    expectedChallenge: "challenge123",
                },
            } as unknown as Request;

            // Act
            await strategy.authenticate(req);
            await new Promise(setImmediate); // Ensure Jest waits for all async calls

            // Assert
            expect(options.findPasskeyByCredentialID).toHaveBeenCalledWith(mockCredentialID);
            expect(verifyAuthenticationResponse).toHaveBeenCalled();
            expect(options.updatePasskeyCounter).toHaveBeenCalledWith(mockCredentialID, mockNewCounter);
            expect(strategy.success).toHaveBeenCalledWith(mockUserID);
        });

        it("should fail authentication if response or challenge is missing", async () => {
            // Arrange
            const req = {
                path: "/login-callback",
                body: {},
            } as unknown as Request;

            // Act
            await strategy.authenticate(req);
            await new Promise(setImmediate);

            // Assert
            expect(strategy.fail).toHaveBeenCalledWith(
                { message: "Missing response or challenge" },
                400
            );
        });

        it("should fail authentication if passkey is not found", async () => {
            // Arrange
            const mockCredentialID = "nonexistentCredential";
            (options.findPasskeyByCredentialID as jest.Mock).mockResolvedValue(null);

            const req = {
                path: "/login-callback",
                body: {
                    response: { id: mockCredentialID },
                    expectedChallenge: "challenge123",
                },
            } as unknown as Request;

            // Act
            await strategy.authenticate(req);
            await new Promise(setImmediate);

            // Assert
            expect(strategy.fail).toHaveBeenCalledWith(
                { message: "Credential not found" },
                404
            );
        });

        it("should fail authentication if verification fails", async () => {
            // Arrange
            const mockUserID = "user123";
            const mockCredentialID = "credential123";
            const mockPublicKey = new Uint8Array([1, 2, 3]);

            const mockPasskey: Passkey = {
                id: mockCredentialID,
                publicKey: mockPublicKey,
                userID: mockUserID,
                webauthnUserID: "webauthnUser123",
                counter: 99,
                transports: ["usb"],
            };

            (options.findPasskeyByCredentialID as jest.Mock).mockResolvedValue(mockPasskey);
            (verifyAuthenticationResponse as jest.Mock).mockResolvedValue({ verified: false });

            const req = {
                path: "/login-callback",
                body: {
                    response: { id: mockCredentialID },
                    expectedChallenge: "challenge123",
                },
            } as unknown as Request;

            // Act
            await strategy.authenticate(req);
            await new Promise(setImmediate);

            // Assert
            expect(strategy.fail).toHaveBeenCalledWith(
                { message: "Verification failed" },
                403
            );
        });
    });

    describe("handleRegistration", () => {
        it("should register successfully with valid credentials", async () => {
            // Arrange
            const mockUserID = "user123";
            const mockCredentialID = "credential123";
            const mockPublicKey = new Uint8Array([1, 2, 3]);
            const mockNewCounter = 100;

            const mockRegistrationInfo = {
                credential: {
                    id: mockCredentialID,
                    publicKey: mockPublicKey,
                    counter: mockNewCounter,
                    transports: ["usb"],
                },
                credentialDeviceType: "singleDevice" as const,
                credentialBackedUp: false,
            };

            (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
                verified: true,
                registrationInfo: mockRegistrationInfo,
            });

            (options.registerPasskey as jest.Mock).mockResolvedValue(undefined);

            const req = {
                path: "/register-callback",
                body: {
                    response: { id: mockCredentialID },
                    expectedChallenge: "challenge123",
                    userID: mockUserID,
                },
            } as unknown as Request;

            // Act
            await strategy.authenticate(req);
            await new Promise(setImmediate);

            // Assert
            expect(verifyRegistrationResponse).toHaveBeenCalled();
            expect(options.registerPasskey).toHaveBeenCalledWith(mockUserID, expect.any(Object));
            expect(strategy.success).toHaveBeenCalledWith(mockUserID);
        });

        it("should fail registration if response, challenge, or userID is missing", async () => {
            // Arrange
            const req = {
                path: "/register-callback",
                body: {},
            } as unknown as Request;

            // Act
            await strategy.authenticate(req);
            await new Promise(setImmediate);

            // Assert
            expect(strategy.fail).toHaveBeenCalledWith(
                { message: "Missing response, challenge, or userID" },
                400
            );
        });

        it("should fail registration if verification fails", async () => {
            // Arrange
            const mockUserID = "user123";
            const mockCredentialID = "credential123";

            (verifyRegistrationResponse as jest.Mock).mockResolvedValue({
                verified: false,
                registrationInfo: null,
            });

            const req = {
                path: "/register-callback",
                body: {
                    response: { id: mockCredentialID },
                    expectedChallenge: "challenge123",
                    userID: mockUserID,
                },
            } as unknown as Request;

            // Act
            await strategy.authenticate(req);
            await new Promise(setImmediate);

            // Assert
            expect(strategy.fail).toHaveBeenCalledWith(
                { message: "Registration verification failed" },
                403
            );
        });
    });
});