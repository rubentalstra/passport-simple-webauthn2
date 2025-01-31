// src/models/user.ts

import {UserModel, Passkey} from "passport-simple-webauthn2";

const users = new Map<string, UserModel>();

/**
 * Finds a user by their ID.
 * @param id - The user's unique identifier.
 * @returns The user or null if not found.
 */
export const findUserById = async (id: string): Promise<UserModel | null> => {
    return users.get(id) || null;
};

/**
 * Finds a user by their WebAuthn user ID.
 * @param webauthnUserID - The WebAuthn user ID.
 * @returns The user or null if not found.
 */
export const findUserByWebAuthnID = async (webauthnUserID: string): Promise<UserModel | null> => {
    for (const user of users.values()) {
        if (user.id === webauthnUserID) {
            return user;
        }
    }
    return null;
};

/**
 * Creates a new user.
 * @param username - The username.
 * @returns The created user.
 */
export const createUser = async (username: string): Promise<UserModel> => {
    const id = `user-${Date.now()}`;
    const user: UserModel = {
        id,
        username,
    };
    users.set(id, user);
    return user;
};