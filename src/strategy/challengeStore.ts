interface ChallengeEntry {
  challenge: string;
  expiresAt: number;
}

const challengeStore = new Map<string, ChallengeEntry>();

export const saveChallenge = async (
  userId: string,
  challenge: string,
  ttl = 300000,
): Promise<void> => {
  challengeStore.set(userId, { challenge, expiresAt: Date.now() + ttl });
  setTimeout(() => challengeStore.delete(userId), ttl);
};

export const getChallenge = async (userId: string): Promise<string | null> => {
  const entry = challengeStore.get(userId);
  if (!entry || Date.now() > entry.expiresAt) {
    challengeStore.delete(userId);
    return null;
  }
  return entry.challenge;
};

export const clearChallenge = async (userId: string): Promise<void> => {
  challengeStore.delete(userId);
};

/**
 * Resets the entire challenge store, clearing all stored challenges.
 */
export const resetChallengeStore = (): void => {
  challengeStore.clear();
};
