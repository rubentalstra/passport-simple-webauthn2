/**
 * @module SimpleWebAuthnStrategy
 * @description
 * This module exports the main components of the SimpleWebAuthnStrategy package,
 * including the strategy class, registration and authentication utilities,
 * challenge store management functions, and type definitions.
 */

export { SimpleWebAuthnStrategy } from "./strategy/SimpleWebAuthnStrategy";
export {
  generateRegistration,
  verifyRegistration,
} from "./strategy/registration";
export {
  saveChallenge,
  getChallenge,
  clearChallenge,
  resetChallengeStore,
} from "./strategy/challengeStore";
export type { Passkey, UserModel } from "./models/types";
