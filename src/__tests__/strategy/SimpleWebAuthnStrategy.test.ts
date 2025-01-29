import { SimpleWebAuthnStrategy, SimpleWebAuthnStrategyOptions } from "../../strategy/SimpleWebAuthnStrategy";
import passport from "passport";
import { verifyAuthentication } from "../../index";
import type { VerifiedAuthenticationResponse, WebAuthnCredential } from "@simplewebauthn/server";
import { Strategy as PassportStrategy } from "passport-strategy";

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

    it("should call fail when userId is missing", () => {
        reqMock.body = { response: {} };

        const failMock = jest.spyOn(strategy, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(strategy, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(strategy, "error").mockImplementation(() => {});

        strategy.authenticate(reqMock);

        expect(failMock).toHaveBeenCalledWith({ message: "Missing userId or response" }, 400);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();
    });

    it("should call fail when response is missing", () => {
        reqMock.body = { userId: "dXNlcklk" }; // 'userId' in base64url

        const failMock = jest.spyOn(strategy, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(strategy, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(strategy, "error").mockImplementation(() => {});

        strategy.authenticate(reqMock);

        expect(failMock).toHaveBeenCalledWith({ message: "Missing userId or response" }, 400);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();
    });

    it("should call fail when user is not found", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(null);

        const failMock = jest.spyOn(strategy, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(strategy, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(strategy, "error").mockImplementation(() => {});

        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(failMock).toHaveBeenCalledWith({ message: "User not found" }, 404);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();
    });

    it("should call fail when verification is not successful", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(userMock);
        mockedVerifyAuthentication.mockResolvedValue({ verified: false });

        const failMock = jest.spyOn(strategy, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(strategy, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(strategy, "error").mockImplementation(() => {});

        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(mockedVerifyAuthentication).toHaveBeenCalledWith(reqMock, userMock, reqMock.body.response);
        expect(failMock).toHaveBeenCalledWith({ message: "Verification failed" }, 403);
        expect(successMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();
    });

    it("should call success when authentication is successful", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockResolvedValue(userMock);
        mockedVerifyAuthentication.mockResolvedValue({ verified: true });

        const failMock = jest.spyOn(strategy, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(strategy, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(strategy, "error").mockImplementation(() => {});

        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(mockedVerifyAuthentication).toHaveBeenCalledWith(reqMock, userMock, reqMock.body.response);
        expect(successMock).toHaveBeenCalledWith(userMock);
        expect(failMock).not.toHaveBeenCalled();
        expect(errorMock).not.toHaveBeenCalled();
    });

    it("should handle errors by calling error method", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockRejectedValue(new Error("Database error"));

        const failMock = jest.spyOn(strategy, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(strategy, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(strategy, "error").mockImplementation(() => {});

        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(errorMock).toHaveBeenCalledWith(new Error("Database error"));
        expect(failMock).not.toHaveBeenCalled();
        expect(successMock).not.toHaveBeenCalled();
    });

    it("should handle non-Error exceptions by calling error with generic message", async () => {
        reqMock.body = { userId: "dXNlcklk", response: {} };
        getUserMock.mockRejectedValue("Unknown error");

        const failMock = jest.spyOn(strategy, "fail").mockImplementation(() => {});
        const successMock = jest.spyOn(strategy, "success").mockImplementation(() => {});
        const errorMock = jest.spyOn(strategy, "error").mockImplementation(() => {});

        await strategy.authenticate(reqMock);

        expect(getUserMock).toHaveBeenCalledWith(reqMock, Buffer.from("dXNlcklk", "base64url"));
        expect(errorMock).toHaveBeenCalledWith(new Error("An unknown error occurred"));
        expect(failMock).not.toHaveBeenCalled();
        expect(successMock).not.toHaveBeenCalled();
    });
});