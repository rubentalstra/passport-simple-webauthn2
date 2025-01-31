/**
 * @module SimpleWebAuthnStrategy
 * @description
 * This module exports the main components of the SimpleWebAuthnStrategy package,
 * including the strategy class, registration and authentication utilities,
 * challenge store management functions, and type definitions.
 */

export * from "./types";
export * from "./strategy/simpleWebAuthnStrategy";
export * from "./auth/registration";
export * from "./strategy/verifyAuthentication";
export * from "./challengeStore";
