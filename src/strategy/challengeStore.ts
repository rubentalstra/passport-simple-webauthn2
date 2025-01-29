import type { Request } from "express";

const challengeStore = new Map<string, string>();

export const saveChallenge = async (
  req: Request,
  userId: string,
  challenge: string,
): Promise<void> => {
  challengeStore.set(userId, challenge);
};

export const getChallenge = async (
  req: Request,
  userId: string,
): Promise<string | null> => {
  return challengeStore.get(userId) || null;
};

export const clearChallenge = async (
  req: Request,
  userId: string,
): Promise<void> => {
  challengeStore.delete(userId);
};
