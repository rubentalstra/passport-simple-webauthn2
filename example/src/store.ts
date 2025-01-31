// src/store.ts

import {Passkey, UserModel} from "passport-simple-webauthn2";

export const users = new Map<string, UserModel>();
export const passkeys = new Map<string, Passkey>();