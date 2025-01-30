import type { Request } from "express";

/**
 * Interface representing a challenge entry.
 */
interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

/**
 * In-memory store for managing challenges associated with user IDs.
 * This store is resettable and is not persistent across server restarts.
 * **Note:** For production, consider using a persistent store like Redis.
 */
const challengeStore = new Map<string, ChallengeEntry>();

/**
 * Saves a challenge for a specific user ID in the challenge store.
 * @param req - The Express request object.
 * @param userId - The user ID.
 * @param challenge - The challenge string to be saved.
 * @param ttl - Time-to-live (TTL) for the challenge in milliseconds (default: 5 minutes).
 */
export const saveChallenge = async (
  req: Request,
  userId: string,
  challenge: string,
  ttl: number = 300000, // 5 minutes
): Promise<void> => {
  if (!userId || !challenge) throw new Error("Invalid userId or challenge");

  challengeStore.set(userId, {
    challenge,
    expiresAt: Date.now() + ttl,
  });

  // Set automatic cleanup
  setTimeout(() => {
    challengeStore.delete(userId);
  }, ttl);
};

/**
 * Retrieves a challenge for a specific user ID from the challenge store.
 * @param req - The Express request object.
 * @param userId - The user ID.
 * @returns A promise that resolves to the challenge string or null if not found or expired.
 */
export const getChallenge = async (
  req: Request,
  userId: string,
): Promise<string | null> => {
  const entry = challengeStore.get(userId);
  if (!entry) return null;

  // Check if the challenge has expired
  if (Date.now() > entry.expiresAt) {
    challengeStore.delete(userId);
    return null;
  }

  return entry.challenge;
};

/**
 * Clears the challenge associated with a specific user ID from the challenge store.
 * @param req - The Express request object.
 * @param userId - The user ID.
 */
export const clearChallenge = async (
  req: Request,
  userId: string,
): Promise<void> => {
  challengeStore.delete(userId);
};

/**
 * Resets the entire challenge store, clearing all stored challenges.
 */
export const resetChallengeStore = (): void => {
  challengeStore.clear();
};
