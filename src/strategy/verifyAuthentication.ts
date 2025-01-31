import type {
  AuthenticationResponseJSON,
  VerifiedAuthenticationResponse,
} from "@simplewebauthn/server";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { Passkey } from "../types";

/**
 * Verifies the authentication response from the client.
 * @param response - The authentication response JSON from the client.
 * @param expectedChallenge - The expected challenge (retrieved externally).
 * @param findPasskey - Function to retrieve a passkey by credential ID.
 * @param updatePasskeyCounter - Function to update passkey counter.
 * @returns A promise that resolves to the verified authentication response.
 */
export const verifyAuthentication = async (
  response: AuthenticationResponseJSON,
  expectedChallenge: string,
  findPasskey: (credentialID: string) => Promise<Passkey | null>,
  updatePasskeyCounter: (
    credentialID: string,
    newCounter: number,
  ) => Promise<void>,
): Promise<VerifiedAuthenticationResponse> => {
  try {
    if (!response || !response.id) {
      throw new Error("Invalid authentication response");
    }

    const passkey: Passkey | null = await findPasskey(response.id);
    if (!passkey) {
      throw new Error("Passkey not found or does not exist");
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
      expectedRPID: process.env.RP_ID || "example.com",
      credential: {
        id: passkey.id,
        publicKey: passkey.publicKey,
        counter: passkey.counter,
        transports: passkey.transports ?? [],
      },
      requireUserVerification: true,
    });

    if (!verification.verified) {
      throw new Error("Authentication failed");
    }

    await updatePasskeyCounter(
      passkey.id,
      verification.authenticationInfo.newCounter,
    );

    return verification;
  } catch (error: any) {
    throw new Error(
      error instanceof Error ? error.message : "Unknown authentication error",
    );
  }
};
