// src/__tests__/strategy/SimpleWebAuthnStrategy.test.ts
jest.mock("../../strategy/authentication");
jest.mock("@simplewebauthn/server");

import { SimpleWebAuthnStrategy, SimpleWebAuthnStrategyOptions } from "../../strategy/SimpleWebAuthnStrategy";
import passport from "passport";
import { verifyAuthentication } from "../../index";
import type { WebAuthnCredential } from "@simplewebauthn/server";
import { Strategy as PassportStrategy } from "passport-strategy";

const mockedVerifyAuthentication = verifyAuthentication as jest.MockedFunction<typeof verifyAuthentication>;

describe("SimpleWebAuthnStrategy", () => {
    let strategy: SimpleWebAuthnStrategy;
    let getUserMock: jest.Mock;
    let reqMock: any;
    let userMock: { id: Uint8Array; credentials: WebAuthnCredential[] };

    beforeEach(() => {
        getUserMock = jest.fn();

        const options: SimpleWebAuthnStrategyOptions = {
            getUser: getUserMock,
        };

        strategy = new SimpleWebAuthnStrategy(options);

        // Initialize Passport to register the strategy
        passport.use(strategy);

        // Mock request
        reqMock = {
            body: {},
        };

        // Mock user
        userMock = {
            id: new Uint8Array([1, 2, 3, 4]),
            credentials: [],
        };
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    it("should call fail when userId is missing", async () => {
        reqMock.body = { response: {} };

        // Spy on the prototype methods
        const failMock = jest.spyOn(PassportStrategy.prototype, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(PassportStrategy.prototype, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(PassportStrategy.prototype, "error").mockImplementation(() => {});

        // Call authenticate
        strategy.authenticate(reqMock);

        expect(failMock).toHaveBeenCalledWith({ message: "Missing userId or response" }, 400);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();

        // Restore mocks
        failMock.mockRestore();
        successMock.mockRestore();
        errorMock.mockRestore();
    });

    it("should call fail when response is missing", async () => {
        reqMock.body = { userId: "dXNlcklk" }; // 'userId' in base64url

        // Spy on the prototype methods
        const failMock = jest.spyOn(PassportStrategy.prototype, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(PassportStrategy.prototype, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(PassportStrategy.prototype, "error").mockImplementation(() => {});

        // Call authenticate
        strategy.authenticate(reqMock);

        expect(failMock).toHaveBeenCalledWith({ message: "Missing userId or response" }, 400);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();

        // Restore mocks
        failMock.mockRestore();
        successMock.mockRestore();
        errorMock.mockRestore();
    });

    it("should call fail when user is not found", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(null);

        // Spy on the prototype methods
        const failMock = jest.spyOn(PassportStrategy.prototype, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(PassportStrategy.prototype, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(PassportStrategy.prototype, "error").mockImplementation(() => {});

        // Call authenticate
        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(failMock).toHaveBeenCalledWith({ message: "User not found" }, 404);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();

        // Restore mocks
        failMock.mockRestore();
        successMock.mockRestore();
        errorMock.mockRestore();
    });

    it("should call fail when verification is not successful", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(userMock);
        mockedVerifyAuthentication.mockResolvedValue({
            verified: false,
            authenticationInfo: {
                newCounter: 0,
                credentialID: Buffer.from(new Uint8Array()).toString("base64"),
                userVerified: false,
                credentialDeviceType: "singleDevice",
                credentialBackedUp: false,
                origin: "https://example.com",
                rpID: "example.com",
            },
        });

        // Spy on the prototype methods
        const failMock = jest.spyOn(PassportStrategy.prototype, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(PassportStrategy.prototype, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(PassportStrategy.prototype, "error").mockImplementation(() => {});

        // Call authenticate
        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(mockedVerifyAuthentication).toHaveBeenCalledWith(reqMock, userMock, reqMock.body.response);
        expect(failMock).toHaveBeenCalledWith({ message: "Verification failed" }, 403);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();

        // Restore mocks
        failMock.mockRestore();
        successMock.mockRestore();
        errorMock.mockRestore();
    });

    it("should call success when authentication is successful", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(userMock);
        mockedVerifyAuthentication.mockResolvedValue({
            verified: true,
            authenticationInfo: {
                newCounter: 0,
                credentialID: Buffer.from(new Uint8Array()).toString("base64"), // Convert Uint8Array to Base64 string
                userVerified: true,
                credentialDeviceType: "singleDevice",
                credentialBackedUp: false,
                origin: "https://example.com",
                rpID: "example.com",
            },
        });

        // Spy on the prototype methods
        const failMock = jest.spyOn(PassportStrategy.prototype, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(PassportStrategy.prototype, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(PassportStrategy.prototype, "error").mockImplementation(() => {});

        // Call authenticate
        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(mockedVerifyAuthentication).toHaveBeenCalledWith(reqMock, userMock, reqMock.body.response);
        expect(successMock).toHaveBeenCalledWith(userMock);
        expect(failMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();

        // Restore mocks
        failMock.mockRestore();
        successMock.mockRestore();
        errorMock.mockRestore();
    });

    it("should handle errors by calling error method", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockRejectedValue(new Error("Database error"));

        // Spy on the prototype methods
        const failMock = jest.spyOn(PassportStrategy.prototype, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(PassportStrategy.prototype, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(PassportStrategy.prototype, "error").mockImplementation(() => {});

        // Call authenticate
        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(errorMock).toHaveBeenCalledWith(new Error("Database error"));
        expect(failMock).not.toHaveBeenCalled();
        expect(successMock).not.toHaveBeenCalled();

        // Restore mocks
        failMock.mockRestore();
        successMock.mockRestore();
        errorMock.mockRestore();
    });

    it("should handle non-Error exceptions by calling error with generic message", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockRejectedValue("Unknown error");

        // Spy on the prototype methods
        const failMock = jest.spyOn(PassportStrategy.prototype, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(PassportStrategy.prototype, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(PassportStrategy.prototype, "error").mockImplementation(() => {});

        // Call authenticate
        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(errorMock).toHaveBeenCalledWith(new Error("An unknown error occurred"));
        expect(failMock).not.toHaveBeenCalled();
        expect(successMock).not.toHaveBeenCalled();

        // Restore mocks
        failMock.mockRestore();
        successMock.mockRestore();
        errorMock.mockRestore();
    });
});