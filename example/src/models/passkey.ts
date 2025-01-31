// src/models/passkey.ts

import type { Passkey, UserModel } from "../types";

const passkeys = new Map<string, Passkey>();

/**
 * Finds a passkey by its credential ID.
 * @param credentialID - The credential ID.
 * @returns The passkey or null if not found.
 */
export const findPasskeyByCredentialID = async (credentialID: string): Promise<Passkey | null> => {
    return passkeys.get(credentialID) || null;
};

/**
 * Updates the counter of a passkey.
 * @param credentialID - The credential ID.
 * @param newCounter - The new counter value.
 */
export const updatePasskeyCounter = async (credentialID: string, newCounter: number): Promise<void> => {
    const passkey = passkeys.get(credentialID);
    if (passkey) {
        passkey.counter = newCounter;
        passkeys.set(credentialID, passkey);
    }
};

/**
 * Registers a new passkey for a user.
 * @param user - The user.
 * @param passkey - The passkey to register.
 */
export const registerPasskey = async (user: UserModel, passkey: Passkey): Promise<void> => {
    passkeys.set(passkey.id, passkey);
    user.passkeys.push(passkey);
};