interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

const challengeStore = new Map<string, ChallengeEntry>();

/**
 * Saves a challenge associated with a user ID.
 * @param userId - The user's unique identifier.
 * @param challenge - The challenge string.
 * @param ttl - Time-to-live in milliseconds (default: 5 minutes).
 */
export const saveChallenge = async (
  userId: string,
  challenge: string,
  ttl = 300000,
): Promise<void> => {
  challengeStore.set(userId, { challenge, expiresAt: Date.now() + ttl });
  setTimeout(() => challengeStore.delete(userId), ttl);
};

/**
 * Retrieves a challenge by user ID.
 * @param userId - The user's unique identifier.
 * @returns The challenge string or null if not found or expired.
 */
export const getChallenge = async (userId: string): Promise<string | null> => {
  const entry = challengeStore.get(userId);
  if (!entry || Date.now() > entry.expiresAt) {
    challengeStore.delete(userId);
    return null;
  }
  return entry.challenge;
};

/**
 * Clears a challenge associated with a user ID.
 * @param userId - The user's unique identifier.
 */
export const clearChallenge = async (userId: string): Promise<void> => {
  challengeStore.delete(userId);
};

/**
 * Resets the entire challenge store, clearing all stored challenges.
 */
export const resetChallengeStore = (): void => {
  challengeStore.clear();
};
