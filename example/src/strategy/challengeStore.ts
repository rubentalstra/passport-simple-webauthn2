// src/strategy/challengeStore.ts

import NodeCache from 'node-cache';

// Simple in-memory challenge store using NodeCache
const challengeCache = new NodeCache({ stdTTL: 300, checkperiod: 60 }); // TTL: 5 minutes

export const saveChallenge = async (userId: string, challenge: string): Promise<void> => {
    challengeCache.set(userId, challenge);
};

export const getChallenge = async (userId: string): Promise<string | undefined> => {
    return challengeCache.get<string>(userId);
};

export const clearChallenge = async (userId: string): Promise<void> => {
    challengeCache.del(userId);
};