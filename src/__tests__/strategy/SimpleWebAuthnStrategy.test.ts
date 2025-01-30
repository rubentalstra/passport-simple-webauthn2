// src/__tests__/strategy/SimpleWebAuthnStrategy.test.ts

import { SimpleWebAuthnStrategy, SimpleWebAuthnStrategyOptions } from "../../strategy/SimpleWebAuthnStrategy";
import passport from "passport";
import { verifyAuthentication } from "../../index";
import type { WebAuthnCredential } from "@simplewebauthn/server";

jest.mock("../../strategy/authentication");

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

        // Override fail, success, and error to allow Jest to track calls
        strategy.fail = jest.fn();
        strategy.success = jest.fn();
        strategy.error = jest.fn();

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

    it("should call fail when userId is missing", (done) => {
        reqMock.body = { response: {} };

        // Override fail to check the call and finish the test
        strategy.fail = (info: any, status?: number) => {
            try {
                expect(info).toEqual({ message: "Missing userId or response" });
                expect(status).toBe(400);
                expect(strategy.success).not.toHaveBeenCalled();
                expect(strategy.error).not.toHaveBeenCalled();
                done();
            } catch (error) {
                done(error);
            }
        };

        // Call authenticate
        strategy.authenticate(reqMock);
    });

    it("should call fail when response is missing", (done) => {
        reqMock.body = { userId: "dXNlcklk" }; // 'userId' in base64url

        // Override fail to check the call and finish the test
        strategy.fail = (info: any, status?: number) => {
            try {
                expect(info).toEqual({ message: "Missing userId or response" });
                expect(status).toBe(400);
                expect(strategy.success).not.toHaveBeenCalled();
                expect(strategy.error).not.toHaveBeenCalled();
                done();
            } catch (error) {
                done(error);
            }
        };

        // Call authenticate
        strategy.authenticate(reqMock);
    });

    it("should call fail when user is not found", (done) => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(null);

        // Override fail to check the call and finish the test
        strategy.fail = (info: any, status?: number) => {
            try {
                expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
                expect(info).toEqual({ message: "User not found" });
                expect(status).toBe(404);
                expect(strategy.success).not.toHaveBeenCalled();
                expect(strategy.error).not.toHaveBeenCalled();
                done();
            } catch (error) {
                done(error);
            }
        };

        // Call authenticate
        strategy.authenticate(reqMock);
    });

    it("should call fail when verification is not successful", (done) => {
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

        // Override fail to check the call and finish the test
        strategy.fail = (info: any, status?: number) => {
            try {
                expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
                expect(mockedVerifyAuthentication).toHaveBeenCalledWith(reqMock, userMock, reqMock.body.response);
                expect(info).toEqual({ message: "Verification failed" });
                expect(status).toBe(403);
                expect(strategy.success).not.toHaveBeenCalled();
                expect(strategy.error).not.toHaveBeenCalled();
                done();
            } catch (error) {
                done(error);
            }
        };

        // Call authenticate
        strategy.authenticate(reqMock);
    });

    it("should call success when authentication is successful", (done) => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(userMock);
        mockedVerifyAuthentication.mockResolvedValue({
            verified: true,
            authenticationInfo: {
                newCounter: 0,
                credentialID: Buffer.from(new Uint8Array()).toString("base64"),
                userVerified: true,
                credentialDeviceType: "singleDevice",
                credentialBackedUp: false,
                origin: "https://example.com",
                rpID: "example.com",
            },
        });

        // Override success to check the call and finish the test
        strategy.success = (user: any) => {
            try {
                expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
                expect(mockedVerifyAuthentication).toHaveBeenCalledWith(reqMock, userMock, reqMock.body.response);
                expect(user).toEqual(userMock);
                expect(strategy.fail).not.toHaveBeenCalled();
                expect(strategy.error).not.toHaveBeenCalled();
                done();
            } catch (error) {
                done(error);
            }
        };

        // Call authenticate
        strategy.authenticate(reqMock);
    });

    it("should handle errors by calling error method", (done) => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        const error = new Error("Database error");
        getUserMock.mockRejectedValue(error);

        // Override error to check the call and finish the test
        strategy.error = (err: any) => {
            try {
                expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
                expect(err).toEqual(error);
                expect(strategy.fail).not.toHaveBeenCalled();
                expect(strategy.success).not.toHaveBeenCalled();
                done();
            } catch (error) {
                done(error);
            }
        };

        // Call authenticate
        strategy.authenticate(reqMock);
    });

    it("should handle non-Error exceptions by calling error with generic message", (done) => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockRejectedValue("Unknown error");

        // Override error to check the call and finish the test
        strategy.error = (err: any) => {
            try {
                expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
                expect(err).toEqual(new Error("An unknown error occurred"));
                expect(strategy.fail).not.toHaveBeenCalled();
                expect(strategy.success).not.toHaveBeenCalled();
                done();
            } catch (error) {
                done(error);
            }
        };

        // Call authenticate
        strategy.authenticate(reqMock);
    });
});