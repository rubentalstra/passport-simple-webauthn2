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

export async function getAllUsers() {
    return Array.from(users.values());
}

/**
 * Finds a user by their ID.
 */
export const findUserById = async (id: string): Promise<User | null> => {
    return users.get(id) || null;
};

/**
 * Finds a user by their username.
 */
export const findUserByUsername = (username: string): User | undefined => {
    return [...users.values()].find(user => user.username === username);
};

/**
 * Creates a new user.
 */
export const createUser = (username: string): User => {
    const id = crypto.randomBytes(16).toString("hex");
    const user: User = { id, username, credentials: [] };
    users.set(id, user);
    return user;
};


export async function updateUser(id: string, data: Partial<any>) {
    const user = users.get(id);
    if (user) {
        Object.assign(user, data);
        users.set(id, user);
    }
}