import type { WebAuthnCredential } from "@simplewebauthn/server";

export interface WebAuthnUser {
  userID: string;
  username: string;
  passkeys: WebAuthnCredential[];
}

export interface UserStore {
  get(identifier: string, byID?: boolean): Promise<WebAuthnUser | undefined>;
  save(user: WebAuthnUser): Promise<void>;
}

export interface ChallengeStore {
  get(userID: string): Promise<string | undefined>;
  save(userID: string, challenge: string): Promise<void>;
  delete(userID: string): Promise<void>;
}
