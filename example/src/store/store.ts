// store/store.ts
import {Passkey} from "passport-simple-webauthn2";

// In-memory user store

interface User {
    id: string;
    username: string;
}

export const users: Map<string, User> = new Map();

// In-memory passkey store
export const passkeys: Map<string, Passkey> = new Map();

// Mapping from WebAuthn User ID to User ID
export const userCredentialMap: Map<string, string> = new Map();