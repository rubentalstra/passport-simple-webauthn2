import { Strategy } from "passport-strategy";
import type { Request } from "express";
import type {
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
} from "@simplewebauthn/server";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import { getChallenge, clearChallenge } from "./challengeStore";
import type { UserModel, Passkey } from "../models/types";

/**
 * Options for the SimpleWebAuthnStrategy.
 */
interface SimpleWebAuthnStrategyOptions {
  findPasskeyByCredentialID: (credentialID: string) => Promise<Passkey | null>;
  updatePasskeyCounter: (
    credentialID: string,
    newCounter: number,
  ) => Promise<void>;
  findUserByWebAuthnID: (webauthnUserID: string) => Promise<UserModel | null>;
  registerPasskey: (user: UserModel, passkey: Passkey) => Promise<void>;
}

/**
 * Passport strategy for WebAuthn authentication.
 */
export class SimpleWebAuthnStrategy extends Strategy {
  public name = "simple-webauthn";

  private readonly findPasskeyByCredentialID: SimpleWebAuthnStrategyOptions["findPasskeyByCredentialID"];
  private readonly updatePasskeyCounter: SimpleWebAuthnStrategyOptions["updatePasskeyCounter"];
  private readonly findUserByWebAuthnID: SimpleWebAuthnStrategyOptions["findUserByWebAuthnID"];
  private readonly registerPasskey: SimpleWebAuthnStrategyOptions["registerPasskey"];

  constructor(options: SimpleWebAuthnStrategyOptions) {
    super();
    this.findPasskeyByCredentialID = options.findPasskeyByCredentialID;
    this.updatePasskeyCounter = options.updatePasskeyCounter;
    this.findUserByWebAuthnID = options.findUserByWebAuthnID;
    this.registerPasskey = options.registerPasskey;
  }

  authenticate(req: Request): void {
    const action = req.path.split("/").pop();
    if (action === "login") {
      this.handleAuthentication(req);
    } else if (action === "register") {
      this.handleRegistration(req);
    } else {
      this.fail({ message: "Unknown action" }, 400);
    }
  }

  private async handleAuthentication(req: Request): Promise<void> {
    try {
      const { response } = req.body;
      if (!response)
        return this.fail({ message: "Missing response data" }, 400);

      const storedChallenge = await getChallenge(response.id);
      if (!storedChallenge)
        return this.fail({ message: "Challenge expired or missing" }, 403);

      const passkey = await this.findPasskeyByCredentialID(response.id);
      if (!passkey) return this.fail({ message: "Credential not found" }, 404);

      const verification: VerifiedAuthenticationResponse =
        await verifyAuthenticationResponse({
          response,
          expectedChallenge: storedChallenge,
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

      if (!verification.verified)
        return this.fail({ message: "Verification failed" }, 403);

      await this.updatePasskeyCounter(
        passkey.id,
        verification.authenticationInfo.newCounter,
      );
      await clearChallenge(response.id);

      this.success(passkey.user);
    } catch (error) {
      this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
    }
  }

  private async handleRegistration(req: Request): Promise<void> {
    try {
      const { response } = req.body;
      if (!response)
        return this.fail({ message: "Missing response data" }, 400);

      const storedChallenge = await getChallenge(response.id);
      if (!storedChallenge)
        return this.fail({ message: "Challenge expired or missing" }, 403);

      const verification: VerifiedRegistrationResponse =
        await verifyRegistrationResponse({
          response,
          expectedChallenge: storedChallenge,
          expectedOrigin: `https://${process.env.RP_ID || "example.com"}`,
          expectedRPID: process.env.RP_ID || "example.com",
          requireUserVerification: true,
        });

      if (!verification.verified || !verification.registrationInfo) {
        return this.fail({ message: "Registration verification failed" }, 403);
      }

      const user = await this.findUserByWebAuthnID(
        verification.registrationInfo.credential.id,
      );
      if (!user) return this.fail({ message: "User not found" }, 404);

      const newPasskey: Passkey = {
        id: verification.registrationInfo.credential.id,
        publicKey: verification.registrationInfo.credential.publicKey,
        counter: verification.registrationInfo.credential.counter,
        webauthnUserID: user.id,
        transports: verification.registrationInfo.credential.transports ?? [],
        deviceType: verification.registrationInfo.credentialDeviceType,
        backedUp: verification.registrationInfo.credentialBackedUp,
        user,
      };

      await this.registerPasskey(user, newPasskey);
      await clearChallenge(response.id);

      this.success(user);
    } catch (error) {
      this.error(
        error instanceof Error ? error : new Error("An unknown error occurred"),
      );
    }
  }
}
