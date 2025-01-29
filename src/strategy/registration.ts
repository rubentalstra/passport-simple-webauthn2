import type { Request } from "express";
import type {
  VerifiedRegistrationResponse,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from "@simplewebauthn/server";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { saveChallenge, getChallenge, clearChallenge } from "./challengeStore";

export interface RegistrationUser {
  id: Uint8Array;
  name: string;
  displayName: string;
  credentials: WebAuthnCredential[];
}

export const generateRegistration = async (
  req: Request,
  user: RegistrationUser,
): Promise<ReturnType<typeof generateRegistrationOptions>> => {
  const options = await generateRegistrationOptions({
    rpName: process.env.RP_NAME || "Example RP",
    rpID: process.env.RP_ID || "example.com",
    userID: user.id,
    userName: user.name,
    attestationType: "direct",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  await saveChallenge(
    req,
    Buffer.from(user.id).toString("base64url"),
    options.challenge,
  );

  return options;
};

export const verifyRegistration = async (
  req: Request,
  user: RegistrationUser,
  response: RegistrationResponseJSON,
): Promise<VerifiedRegistrationResponse> => {
  const userIdBase64 = Buffer.from(user.id).toString("base64url");
  const storedChallenge = await getChallenge(req, userIdBase64);
  if (!storedChallenge) throw new Error("Challenge expired or missing");

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: storedChallenge,
    expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
    expectedRPID: process.env.RP_ID || "example.com",
  });

  if (!verification.verified)
    throw new Error("Registration verification failed");

  await clearChallenge(req, userIdBase64);
  return verification;
};
