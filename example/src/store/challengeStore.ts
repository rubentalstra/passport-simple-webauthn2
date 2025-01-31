// challengeStore.ts

const challenges: Map<string, string> = new Map();

/**
 * Saves a challenge for a given user ID.
 * @param userID - The user's unique identifier.
 * @param challenge - The generated challenge string.
 */
export const saveChallenge = async (userID: string, challenge: string): Promise<void> => {
  challenges.set(userID, challenge);
};

/**
 * Retrieves the saved challenge for a given user ID.
 * @param userID - The user's unique identifier.
 * @returns The challenge string or null if not found.
 */
export const getChallenge = async (userID: string): Promise<string | null> => {
  return challenges.get(userID) || null;
};

/**
 * Clears the saved challenge for a given user ID.
 * @param userID - The user's unique identifier.
 */
export const clearChallenge = async (userID: string): Promise<void> => {
  challenges.delete(userID);
};