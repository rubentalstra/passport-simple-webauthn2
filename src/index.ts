/**
 * @module SimpleWebAuthnStrategy
 */

export { SimpleWebAuthnStrategy } from "./strategy/SimpleWebAuthnStrategy";
export {
  generateRegistration,
  verifyRegistration,
} from "./strategy/registration";
export {
  generateAuthentication,
  verifyAuthentication,
} from "./strategy/authentication";
export {
  saveChallenge,
  getChallenge,
  clearChallenge,
} from "./strategy/challengeStore";
export type { UserModel, Passkey } from "./models/types";
