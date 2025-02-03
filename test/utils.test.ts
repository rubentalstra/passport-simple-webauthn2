// utils.test.ts
import { Buffer } from "buffer";
import {
    bufferToBase64URL,
    serializeOptions,
    getExpectedOrigin,
    normalizePublicKey,
} from "../src/utils";

describe("Utility Functions", () => {
    describe("bufferToBase64URL", () => {
        it("should return the same string if input is a string", () => {
            const input = "plain-string";
            const result = bufferToBase64URL(input);
            expect(result).toBe(input);
        });

        it("should convert a Buffer to a base64url string", () => {
            const input = Buffer.from("hello world");
            const expected = input.toString("base64url");
            const result = bufferToBase64URL(input);
            expect(result).toBe(expected);
        });

        it("should convert an ArrayBuffer to a base64url string", () => {
            const text = "test array buffer";
            const arrayBuffer = Buffer.from(text).buffer; // Create an ArrayBuffer
            const expected = Buffer.from(arrayBuffer).toString("base64url");
            const result = bufferToBase64URL(arrayBuffer);
            expect(result).toBe(expected);
        });
    });

    describe("serializeOptions", () => {
        it("should serialize options by converting the challenge to a base64url string", () => {
            const dummyChallenge = Buffer.from("my-challenge");
            const options = {
                challenge: dummyChallenge,
                foo: "bar",
            };
            const serialized = serializeOptions(options);
            const expectedChallenge = dummyChallenge.toString("base64url");
            expect(serialized).toEqual({
                challenge: expectedChallenge,
                foo: "bar",
            });
        });
    });

    describe("getExpectedOrigin", () => {
        const originalEnv = process.env.NODE_ENV;
        afterEach(() => {
            process.env.NODE_ENV = originalEnv;
        });

        it("should return http://<rpID> if NODE_ENV is development", () => {
            process.env.NODE_ENV = "development";
            const rpID = "localhost";
            const origin = getExpectedOrigin(rpID);
            expect(origin).toBe(`http://${rpID}`);
        });

        it("should return https://<rpID> if NODE_ENV is not development", () => {
            process.env.NODE_ENV = "production";
            const rpID = "example.com";
            const origin = getExpectedOrigin(rpID);
            expect(origin).toBe(`https://${rpID}`);
        });
    });

    describe("normalizePublicKey", () => {
        it("should return a Buffer when publicKey is an object with a buffer property", () => {
            const originalBuffer = Buffer.from("key-data");
            // Simulate an object (for example, a TypedArray-like object) that holds a buffer.
            const publicKeyObj = { buffer: originalBuffer };
            const normalized = normalizePublicKey(publicKeyObj);
            expect(Buffer.isBuffer(normalized)).toBe(true);
            expect(normalized.toString("utf8")).toBe("key-data");
        });

        it("should return a Buffer when publicKey is a string", () => {
            const input = "another-test-key";
            const normalized = normalizePublicKey(input);
            expect(Buffer.isBuffer(normalized)).toBe(true);
            expect(normalized.toString("utf8")).toBe("another-test-key");
        });
    });
});