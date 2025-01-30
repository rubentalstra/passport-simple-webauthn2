// src/models/user.ts
import { Passkey, UserModel } from "";

export interface User extends UserModel {
    credentials: Passkey[];
}

const users: Map<string, User> = new Map();

/**
 * Finds a user by their ID.
 * @param id - The user's unique identifier.
 * @returns The user object or undefined if not found.
 */
export const findUserById = (id: Uint8Array): User | undefined => {
    const userId = Buffer.from(id).toString("base64url");
    return users.get(userId);
};

/**
 * Finds a user by their username.
 * @param username - The user's username.
 * @returns The user object or undefined if not found.
 */
export const findUserByUsername = (username: string): User | undefined => {
    for (const user of users.values()) {
        if (user.username === username) {
            return user;
        }
    }
    return undefined;
};

/**
 * Creates a new user.
 * @param username - The user's username.
 * @returns The created user object.
 */
export const createUser = (username: string): User => {
    const id = crypto.randomBytes(32);
    const user: User = {
        id,
        username,
        credentials: [],
    };
    users.set(Buffer.from(id).toString("base64url"), user);
    return user;
};