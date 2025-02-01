// types.ts
import {WebAuthnCredential} from "@simplewebauthn/server";

export type Base64URLString = string;

export interface User {
    userID: string;
    username: string;
    passkeys: WebAuthnCredential[];
}