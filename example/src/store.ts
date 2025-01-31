// src/store.ts

import { UserModel, Passkey } from './types';

export const users = new Map<string, UserModel>();
export const passkeys = new Map<string, Passkey>();