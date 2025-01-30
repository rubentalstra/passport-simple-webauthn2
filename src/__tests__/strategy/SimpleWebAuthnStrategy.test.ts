import { SimpleWebAuthnStrategy } from "../../strategy/SimpleWebAuthnStrategy";
import passport from "passport";
import { verifyAuthentication } from "../../index";
import type { WebAuthnCredential } from "@simplewebauthn/server";

jest.mock("../../strategy/authentication");

const mockedVerifyAuthentication = verifyAuthentication as jest.MockedFunction<typeof verifyAuthentication>;

describe("SimpleWebAuthnStrategy", () => {
    let strategy: SimpleWebAuthnStrategy;
    let reqMock: any;
    let userMock: { id: string; credentials: WebAuthnCredential[] };

    beforeEach(() => {
        strategy = new SimpleWebAuthnStrategy();

        // Override fail, success, and error to allow Jest to track calls
        strategy.fail = jest.fn();
        strategy.success = jest.fn();
        strategy.error = jest.fn();

        // Initialize Passport to register the strategy
        passport.use(strategy);

        // Mock request
        reqMock = {
            body: {},
            user: undefined, // Initially undefined
        };

        // Mock user
        userMock = {
            id: "user123",
            credentials: [],
        };
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    it("should call fail when req.user is missing", (done) => {
        reqMock.body = { response: {} };

        strategy.fail = (info: any, status?: number) => {
            try {
                expect(info).toEqual({ message: "User not authenticated" });
                expect(status).toBe(401);
                done();
            } catch (error) {
                done(error);
            }
        };

        strategy.authenticate(reqMock);
    });

    it("should call fail when response is missing", (done) => {
        reqMock.user = userMock;
        reqMock.body = {}; // Missing response

        strategy.fail = (info: any, status?: number) => {
            try {
                expect(info).toEqual({ message: "Missing response data" });
                expect(status).toBe(400);
                done();
            } catch (error) {
                done(error);
            }
        };

        strategy.authenticate(reqMock);
    });

    it("should call fail when verification is unsuccessful", (done) => {
        reqMock.user = userMock;
        reqMock.body = { response: {} };

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

        strategy.fail = (info: any, status?: number) => {
            try {
                expect(info).toEqual({ message: "Verification failed" });
                expect(status).toBe(403);
                done();
            } catch (error) {
                done(error);
            }
        };

        strategy.authenticate(reqMock);
    });

    it("should call success when authentication is successful", (done) => {
        reqMock.user = userMock;
        reqMock.body = { response: {} };

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

        strategy.success = (user: any) => {
            try {
                expect(user).toEqual(userMock);
                done();
            } catch (error) {
                done(error);
            }
        };

        strategy.authenticate(reqMock);
    });

    it("should handle errors correctly", (done) => {
        reqMock.user = userMock;
        reqMock.body = { response: {} };
        const error = new Error("Something went wrong");

        mockedVerifyAuthentication.mockRejectedValue(error);

        strategy.error = (err: any) => {
            try {
                expect(err).toEqual(error);
                done();
            } catch (error) {
                done(error);
            }
        };

        strategy.authenticate(reqMock);
    });
});