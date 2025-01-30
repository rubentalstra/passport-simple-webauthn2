import type { Request } from "express";
import type {
  AuthenticationResponseJSON,
  VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { getChallenge, clearChallenge } from "./challengeStore";
import type { UserModel, Passkey } from "../models/types";

/**
 * Verifies the authentication response from the client.
 * @param req - The Express request object.
 * @param response - The authentication response JSON from the client.
 * @returns A promise that resolves to the verified authentication response.
 */
export const verifyAuthentication = async (
  req: Request,
  response: AuthenticationResponseJSON,
): Promise<VerifiedAuthenticationResponse> => {
  if (!req.user) throw new Error("User not authenticated");

  const user = req.user as UserModel;
  const storedChallenge = await getChallenge(req, user.id);
  if (!storedChallenge) throw new Error("Challenge expired or missing");

  const passkey = user.credentials.find((cred) => cred.id === response.id);
  if (!passkey) throw new Error("Credential not found");

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: storedChallenge,
    expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
    expectedRPID: process.env.RP_ID || "example.com",
    credential: {
      id: passkey.id,
      publicKey: passkey.publicKey,
      counter: passkey.counter,
      transports: passkey.transports,
    },
    requireUserVerification: true,
  });

  if (!verification.verified) throw new Error("Authentication failed");

  // Update the counter in your DB to prevent replay attacks
  passkey.counter = verification.authenticationInfo.newCounter;
  await updatePasskeyCounter(passkey); // Implement this function

  await clearChallenge(req, user.id);
  return verification;
};

/**
 * Updates the counter for a passkey in the database.
 * @param passkey - The passkey whose counter needs to be updated.
 */
async function updatePasskeyCounter(passkey: Passkey): Promise<void> {
  // Implement your database update logic here
  // Example using a hypothetical ORM or database client:
  // await db.passkeys.updateOne({ id: passkey.id }, { $set: { counter: passkey.counter } });

  // Placeholder implementation:
  console.log(
    `Updating counter for passkey ID: ${passkey.id} to ${passkey.counter}`,
  );
}
