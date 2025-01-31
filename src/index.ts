import { Strategy as PassportStrategy } from "passport-strategy";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { Request } from "express";
import { v4 as uuidv4 } from "uuid";
import {
  bufferToBase64URL,
  serializeAuthenticationOptions,
  serializeRegistrationOptions,
} from "./utils";
import type { UserStore, WebAuthnUser, ChallengeStore } from "./types";
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/server/esm/types";

export { ChallengeStore, WebAuthnUser, UserStore };

export class WebAuthnStrategy extends PassportStrategy {
  name = "webauthn";
  private readonly rpID: string;
  private readonly rpName: string;
  private readonly userStore: UserStore;
  private readonly challengeStore: ChallengeStore;

  constructor(options: {
    rpID: string;
    rpName: string;
    userStore: UserStore;
    challengeStore: ChallengeStore;
  }) {
    super();
    this.rpID = options.rpID;
    this.rpName = options.rpName;
    this.userStore = options.userStore;
    this.challengeStore = options.challengeStore;
  }

  private async getUser(
    identifier: string,
    byID = false,
  ): Promise<WebAuthnUser | undefined> {
    return this.userStore.get(identifier, byID);
  }

  async registerChallenge(
    req: Request,
    username: string,
  ): Promise<Record<string, unknown>> {
    if (!username) throw new Error("Username required");

    let user = await this.getUser(username);
    if (!user) {
      user = { userID: uuidv4(), username, passkeys: [] };
      await this.userStore.save(user);
    }

    const options = await generateRegistrationOptions({
      rpName: this.rpName || "WebAuthn Demo",
      rpID: this.rpID || "localhost",
      userID: Buffer.from(user.userID, "utf-8"),
      userName: user.username,
      attestationType: "none",
      excludeCredentials: user.passkeys.map((cred) => ({
        id: bufferToBase64URL(cred.id),
        type: "public-key",
        transports: cred.transports || ["internal", "usb", "ble", "nfc"],
      })),
      authenticatorSelection: {
        userVerification: "required",
        residentKey: "required",
        authenticatorAttachment: "platform",
      },
    });

    // Save the challenge (converted to a base64url string)
    await this.challengeStore.save(
      user.userID,
      bufferToBase64URL(options.challenge),
    );
    return serializeRegistrationOptions(options);
  }

  async registerCallback(
    req: Request,
    username: string,
    credential: RegistrationResponseJSON,
  ): Promise<WebAuthnUser> {
    const user = await this.getUser(username);
    if (!user) throw new Error("User not found");

    const challenge = await this.challengeStore.get(user.userID);
    if (!challenge) throw new Error("Challenge not found");

    try {
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin: `https://${this.rpID}`,
        expectedRPID: this.rpID || "localhost",
        requireUserVerification: true,
      });

      await this.challengeStore.delete(user.userID);

      if (!verification.verified || !verification.registrationInfo) {
        throw new Error("Verification failed");
      }

      const { publicKey, id, counter, transports } =
        verification.registrationInfo.credential;

      // Store id as a base64url string and the public key as a Buffer.
      user.passkeys.push({
        id: bufferToBase64URL(id),
        publicKey: new Uint8Array(publicKey),
        counter,
        transports,
      });

      await this.userStore.save(user);
      return user;
    } catch (error) {
      throw new Error(
        error instanceof Error ? error.message : "Registration failed",
      );
    }
  }

  async loginChallenge(
    req: Request,
    username: string,
  ): Promise<Record<string, unknown>> {
    const user = await this.getUser(username);
    if (!user) throw new Error("User not found");

    const platformCredentials = user.passkeys.filter((cred) =>
      cred.transports?.includes("internal"),
    );

    const options = await generateAuthenticationOptions({
      rpID: this.rpID || "localhost",
      userVerification: "required",
      allowCredentials:
        platformCredentials.length > 0
          ? platformCredentials.map((cred) => ({
              id: bufferToBase64URL(cred.id),
              type: "public-key",
              transports: cred.transports,
            }))
          : undefined,
    });

    await this.challengeStore.save(
      user.userID,
      bufferToBase64URL(options.challenge),
    );
    return serializeAuthenticationOptions(options);
  }

  async loginCallback(
    req: Request,
    username: string,
    credential: AuthenticationResponseJSON,
  ): Promise<WebAuthnUser> {
    const user = await this.getUser(username);
    if (!user) throw new Error("User not found");

    const challenge = await this.challengeStore.get(user.userID);
    if (!challenge) throw new Error("Challenge not found");

    // Find the registered passkey by comparing credential ids.
    const passkey = user.passkeys.find(
      (p) => p.id === bufferToBase64URL(credential.id),
    );
    if (!passkey) throw new Error("Passkey not found");

    try {
      const verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin: `https://${process.env.RP_ID}`,
        expectedRPID: process.env.RP_ID || "localhost",
        credential: {
          id: passkey.id,
          publicKey: passkey.publicKey,
          counter: passkey.counter,
          transports: passkey.transports,
        },
        requireUserVerification: true,
      });

      await this.challengeStore.delete(user.userID);

      if (!verification.verified) throw new Error("Verification failed");

      // Update the passkey counter.
      passkey.counter = verification.authenticationInfo.newCounter;
      await this.userStore.save(user);

      return user;
    } catch (error) {
      throw new Error(error instanceof Error ? error.message : "Login failed");
    }
  }

  authenticate(_req: Request): void {
    throw new Error(
      "Use registerChallenge, registerCallback, loginChallenge, or loginCallback instead.",
    );
  }
}
