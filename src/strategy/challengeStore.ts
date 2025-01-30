import type { Request } from "express";

/**
 * In-memory store for managing challenges associated with user IDs.
 * This store is resettable and is not persistent across server restarts.
 */
const challengeStore = new Map<string, string>();

/**
 * Saves a challenge for a specific user ID in the challenge store.
 * @param req - The Express request object.
 * @param userId - The Base64URL-encoded user ID.
 * @param challenge - The challenge string to be saved.
 * @returns A promise that resolves when the challenge is saved.
 * @throws Will throw an error if userId or challenge is invalid.
 */
export const saveChallenge = async (
  req: Request,
  userId: string,
  challenge: string,
): Promise<void> => {
  if (!userId || !challenge) throw new Error("Invalid userId or challenge");
  challengeStore.set(userId, challenge);
};

/**
 * Retrieves a challenge for a specific user ID from the challenge store.
 * @param req - The Express request object.
 * @param userId - The Base64URL-encoded user ID.
 * @returns A promise that resolves to the challenge string or null if not found.
 * @throws Will throw an error if userId is invalid.
 */
export const getChallenge = async (
  req: Request,
  userId: string,
): Promise<string | null> => {
  if (!userId) throw new Error("Invalid userId");
  return challengeStore.get(userId) ?? null;
};

/**
 * Clears the challenge associated with a specific user ID from the challenge store.
 * @param req - The Express request object.
 * @param userId - The Base64URL-encoded user ID.
 * @returns A promise that resolves when the challenge is cleared.
 * @throws Will throw an error if userId is invalid.
 */
export const clearChallenge = async (
  req: Request,
  userId: string,
): Promise<void> => {
  if (!userId) throw new Error("Invalid userId");
  challengeStore.delete(userId);
};

/**
 * Resets the entire challenge store, clearing all stored challenges.
 */
export const resetChallengeStore = (): void => {
  challengeStore.clear();
};
