import type { Request } from "express";

const challengeStore = new Map<string, string>();

export const saveChallenge = async (
  req: Request,
  userId: string,
  challenge: string,
): Promise<void> => {
  if (!userId || !challenge) throw new Error("Invalid userId or challenge");
  challengeStore.set(userId, challenge);
};

export const getChallenge = async (
  req: Request,
  userId: string,
): Promise<string | null> => {
  if (!userId) throw new Error("Invalid userId");
  return challengeStore.get(userId) ?? null;
};

export const clearChallenge = async (
  req: Request,
  userId: string,
): Promise<void> => {
  if (!userId) throw new Error("Invalid userId");
  challengeStore.delete(userId);
};

export const resetChallengeStore = (): void => {
  challengeStore.clear();
};
