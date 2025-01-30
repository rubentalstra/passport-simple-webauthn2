import { Passkey } from "passport-simple-webauthn2";
import crypto from "crypto";

/**
 * Represents a user in the application.
 */
export interface User {
    id: string;
    username: string;
    credentials: Passkey[];
}

const users: Map<string, User> = new Map();

/**
 * Finds a user by their ID.
 * @param id - The user's ID.
 * @returns The user object or undefined if not found.
 */
export const findUserById = (id: string): User | undefined => {
    return users.get(id);
};

/**
 * Finds a user by their username.
 * @param username - The user's username.
 * @returns The user object or undefined if not found.
 */
export const findUserByUsername = (username: string): User | undefined => {
    return [...users.values()].find(user => user.username === username);
};

/**
 * Creates a new user.
 * @param username - The user's username.
 * @returns The created user object.
 */
export const createUser = (username: string): User => {
    const id = crypto.randomBytes(16).toString("hex");
    const user: User = {
        id,
        username,
        credentials: [],
    };
    users.set(id, user);
    return user;
};