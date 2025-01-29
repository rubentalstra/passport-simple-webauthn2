import type { Request } from "express";

/**
 * In-memory store for challenges.
 *
 * **Note:** For production environments, consider using a persistent store like Redis.
 */
const challengeStore = new Map<string, string>();

/**
 * Saves a challenge associated with a user ID.
 *
 * @param req - Express request object.
 * @param userId - The user's base64url-encoded ID.
 * @param challenge - The challenge string to save.
 */
export const saveChallenge = async (
  req: Request,
  userId: string,
  challenge: string,
): Promise<void> => {
  challengeStore.set(userId, challenge);
};

/**
 * Retrieves a stored challenge for a given user ID.
 *
 * @param req - Express request object.
 * @param userId - The user's base64url-encoded ID.
 * @returns The stored challenge string or null if not found.
 */
export const getChallenge = async (
  req: Request,
  userId: string,
): Promise<string | null> => {
  return challengeStore.get(userId) || null;
};

/**
 * Clears a stored challenge for a given user ID.
 *
 * @param req - Express request object.
 * @param userId - The user's base64url-encoded ID.
 */
export const clearChallenge = async (
  req: Request,
  userId: string,
): Promise<void> => {
  challengeStore.delete(userId);
};
