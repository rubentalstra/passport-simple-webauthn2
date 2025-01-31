/**
 * @module SimpleWebAuthnStrategy
 * @description
 * This module exports the main components of the SimpleWebAuthnStrategy package,
 * including the strategy class, registration and authentication utilities,
 * challenge store management functions, and type definitions.
 */

export { SimpleWebAuthnStrategy } from "./strategy/simpleWebAuthnStrategy";
export {
  generateRegistration,
  verifyRegistration,
} from "./strategy/verifyRegistration";
export { verifyAuthentication } from "./strategy/verifyAuthentication";
export {
  saveChallenge,
  getChallenge,
  clearChallenge,
  resetChallengeStore,
} from "./strategy/challengeStore";

export type {
  UserModel,
  Passkey,
  SimpleWebAuthnStrategyOptions,
} from "./types";
