// import type { WebAuthnCredential } from "@simplewebauthn/server";

/* ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
   TYPES
––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––– */
export interface WebAuthnUser {
  id?: string;
  email: string;
  passkeys: any[];
}

export interface UserStore {
  /**
   * Retrieves a user by their unique identifier or by username.
   * - If `byID` is true, the lookup is done by the standardized `id`.
   * - Otherwise, the lookup is done by username.
   */
  get(identifier: string, byID?: boolean): Promise<WebAuthnUser | undefined>;

  /**
   * Saves (or upserts) the user and returns the updated user.
   */
  save(user: WebAuthnUser): Promise<WebAuthnUser>;
}

export interface ChallengeStore {
  /**
   * Retrieves the challenge string for a given user identifier.
   */
  get(userId: string): Promise<string | undefined>;

  /**
   * Saves the challenge string for a given user identifier.
   */
  save(userId: string, challenge: string): Promise<void>;

  /**
   * Deletes the stored challenge for a given user identifier.
   */
  delete(userId: string): Promise<void>;
}
