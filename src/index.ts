/**
 * Passport Strategy that implements "Web Authn (PassKeys)"
 * @author: Ruben Talstra <>
 */

import { Strategy as PassportStrategy } from "passport-strategy";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { Request } from "express";
import { v4 as uuidv4 } from "uuid";
import winston from "winston";
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
  private readonly debug: boolean;
  private readonly logger: winston.Logger;

  constructor(options: {
    rpID: string;
    rpName: string;
    userStore: UserStore;
    challengeStore: ChallengeStore;
    debug?: boolean;
  }) {
    super();
    this.rpID = options.rpID;
    this.rpName = options.rpName;
    this.userStore = options.userStore;
    this.challengeStore = options.challengeStore;
    this.debug = options.debug ?? false;

    this.logger = winston.createLogger({
      level: this.debug ? "debug" : "info",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message, ...meta }) => {
          const metaString = Object.keys(meta).length
            ? JSON.stringify(meta)
            : "";
          return `${timestamp} [WebAuthnStrategy] ${level}: ${message} ${metaString}`;
        }),
      ),
      transports: [new winston.transports.Console()],
    });

    this.logger.info("WebAuthnStrategy initialized", {
      rpID: this.rpID,
      rpName: this.rpName,
      debug: this.debug,
    });
    this.debugLog("Debug logging enabled");
  }

  private debugLog(message: string, ...optionalParams: any[]): void {
    if (this.debug) {
      this.logger.debug(message, ...optionalParams);
    }
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
    this.debugLog(`registerChallenge called for username: ${username}`);
    if (!username) throw new Error("Username required");

    let user = await this.getUser(username);
    if (!user) {
      this.debugLog(
        `User not found. Creating new user for username: ${username}`,
      );
      user = { userID: uuidv4(), username, passkeys: [] };
      await this.userStore.save(user);
      this.debugLog(`New user created with userID: ${user.userID}`);
    } else {
      this.debugLog(`User found with userID: ${user.userID}`);
    }

    this.debugLog("Generating registration options");
    const options = await generateRegistrationOptions({
      rpName: this.rpName || "WebAuthn Demo",
      rpID: this.rpID || "localhost",
      userID: Buffer.from(user.userID, "utf-8"),
      userName: user.username,
      attestationType: "none",
      excludeCredentials: user.passkeys.map((cred) => ({
        id: cred.id,
        type: "public-key",
        transports: cred.transports || ["internal", "usb", "ble", "nfc"],
      })),
      authenticatorSelection: {
        userVerification: "required",
        residentKey: "required",
        authenticatorAttachment: "platform",
      },
    });
    this.debugLog("Registration options generated", {
      challenge: bufferToBase64URL(options.challenge),
      options,
    });

    // Save the challenge (as a base64url string)
    const challengeStr = bufferToBase64URL(options.challenge);
    await this.challengeStore.save(user.userID, challengeStr);
    this.debugLog(`Challenge saved for userID ${user.userID}: ${challengeStr}`);

    const serializedOptions = serializeRegistrationOptions(options);
    this.debugLog("Serialized registration options", serializedOptions);

    this.logger.info(
      `Registration challenge generated for user ${user.username} (ID: ${user.userID})`,
    );

    return serializedOptions;
  }

  async registerCallback(
    req: Request,
    username: string,
    credential: RegistrationResponseJSON,
  ): Promise<WebAuthnUser> {
    this.debugLog(`registerCallback called for username: ${username}`);
    const user = await this.getUser(username);
    if (!user) {
      this.logger.error(`User not found for username: ${username}`);
      throw new Error("User not found");
    }
    this.debugLog(`User found with userID: ${user.userID}`);

    const challenge = await this.challengeStore.get(user.userID);
    if (!challenge) {
      this.logger.error(`Challenge not found for userID: ${user.userID}`);
      throw new Error("Challenge not found");
    }
    this.debugLog(
      `Challenge retrieved for userID ${user.userID}: ${challenge}`,
    );

    try {
      this.debugLog("Verifying registration response", credential);
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin:
          process.env.NODE_ENV === "development"
            ? `http://${this.rpID}`
            : `https://${this.rpID}`,
        expectedRPID: this.rpID || "localhost",
        requireUserVerification: true,
      });
      this.debugLog("Registration response verification result", verification);

      await this.challengeStore.delete(user.userID);
      this.debugLog(`Challenge deleted for userID ${user.userID}`);

      if (!verification.verified || !verification.registrationInfo) {
        this.logger.error("Registration verification failed");
        throw new Error("Verification failed");
      }

      const { publicKey, id, counter, transports } =
        verification.registrationInfo.credential;
      this.debugLog("Storing new passkey", { id, counter, transports });

      // Convert publicKey to Buffer
      const publicKeyBuffer = Buffer.from(
        typeof publicKey === "object" ? Object.values(publicKey) : publicKey,
      );

      const newPasskey = {
        id,
        publicKey: publicKeyBuffer,
        counter,
        transports,
      };

      // Update the user's passkeys and save the user
      user.passkeys.push(newPasskey);
      await this.userStore.save(user);
      this.debugLog("User updated with new passkey", user);

      // *** Return the user object directly ***
      return user;
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Registration failed";
      this.logger.error(`Error during registration callback: ${errorMsg}`);
      this.debugLog(`Error during registration callback: ${errorMsg}`);
      throw new Error(errorMsg);
    }
  }

  async loginChallenge(
    req: Request,
    username: string,
  ): Promise<Record<string, unknown>> {
    this.debugLog(`loginChallenge called for username: ${username}`);
    const user = await this.getUser(username);
    if (!user) {
      this.logger.error(`User not found for username: ${username}`);
      throw new Error("User not found");
    }
    this.debugLog(`User found with userID: ${user.userID}`);

    // Filter for platform authenticators.
    const platformCredentials = user.passkeys.filter((cred) =>
      cred.transports?.includes("internal"),
    );
    this.debugLog("Filtered platform credentials", platformCredentials);

    this.debugLog("Generating authentication options");
    const options = await generateAuthenticationOptions({
      rpID: this.rpID || "localhost",
      userVerification: "required",
      allowCredentials:
        platformCredentials.length > 0
          ? platformCredentials.map((cred) => ({
              id: cred.id, // stored id is already base64url encoded
              type: "public-key",
              transports: cred.transports,
            }))
          : undefined,
    });
    this.debugLog("Authentication options generated", {
      challenge: bufferToBase64URL(options.challenge),
      options,
    });

    const challengeStr = bufferToBase64URL(options.challenge);
    await this.challengeStore.save(user.userID, challengeStr);
    this.debugLog(`Challenge saved for userID ${user.userID}: ${challengeStr}`);

    const serializedOptions = serializeAuthenticationOptions(options);
    this.debugLog("Serialized authentication options", serializedOptions);

    this.logger.info(
      `Login challenge generated for user ${user.username} (ID: ${user.userID})`,
    );
    return serializedOptions;
  }

  async loginCallback(
    req: Request,
    username: string,
    credential: AuthenticationResponseJSON,
  ): Promise<WebAuthnUser> {
    this.debugLog(`loginCallback called for username: ${username}`);
    const user = await this.getUser(username);
    if (!user) {
      this.logger.error(`User not found for username: ${username}`);
      throw new Error("User not found");
    }
    this.debugLog(`User found with userID: ${user.userID}`);

    const challenge = await this.challengeStore.get(user.userID);
    if (!challenge) {
      this.logger.error(`Challenge not found for userID: ${user.userID}`);
      throw new Error("Challenge not found");
    }
    this.debugLog(
      `Challenge retrieved for userID ${user.userID}: ${challenge}`,
    );

    // Find the passkey by its id
    const passkey = user.passkeys.find((p) => p.id === credential.id);
    if (!passkey) {
      this.logger.error(
        `Passkey not found for credential id: ${credential.id}`,
      );
      this.debugLog(`Passkey not found for credential id: ${credential.id}`);
      throw new Error("Passkey not found");
    }
    this.debugLog("Passkey found", passkey);

    try {
      // Normalize the stored public key
      const storedPublicKey =
        passkey.publicKey && (passkey.publicKey as any).buffer
          ? Buffer.from((passkey.publicKey as any).buffer)
          : Buffer.from(passkey.publicKey);

      this.debugLog("Verifying authentication response", credential);
      const verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin:
          process.env.NODE_ENV === "development"
            ? `http://${this.rpID}`
            : `https://${this.rpID}`,
        expectedRPID: this.rpID,
        credential: {
          id: passkey.id,
          publicKey: storedPublicKey,
          counter: passkey.counter,
          transports: passkey.transports,
        },
        requireUserVerification: true,
      });
      this.debugLog(
        "Authentication response verification result",
        verification,
      );

      await this.challengeStore.delete(user.userID);
      this.debugLog(`Challenge deleted for userID ${user.userID}`);

      if (!verification.verified) {
        this.logger.error("Authentication verification failed");
        this.debugLog("Authentication verification failed");
        throw new Error("Verification failed");
      }

      // Update the counter on the passkey and save the user
      passkey.counter = verification.authenticationInfo.newCounter;
      await this.userStore.save(user);
      this.debugLog("User updated with new counter", user);

      // *** Return the user object directly ***
      return user;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Login failed";
      this.logger.error(`Error during login callback: ${errorMsg}`);
      this.debugLog(`Error during login callback: ${errorMsg}`);
      throw new Error(errorMsg);
    }
  }

  /**
   * Fully integrated authenticate() method:
   *
   * Instead of relying on external options, we infer the mode (register or login)
   * from the request path. For example, if the URL contains "register" then mode is "register",
   * and if it contains "login" then mode is "login". You can customize this logic as needed.
   *
   * For GET requests, the strategy returns the generated challenge options.
   * For POST requests, it expects the credential in req.body.credential and verifies it.
   */
  async authenticate(req: Request, _options?: any): Promise<void> {
    // Infer mode based on the request path.
    let mode: "register" | "login";
    if (req.path.toLowerCase().includes("register")) {
      mode = "register";
    } else if (req.path.toLowerCase().includes("login")) {
      mode = "login";
    } else {
      return this.error(
        new Error(
          "Could not infer mode. Please ensure the URL contains either register or login.",
        ),
      );
    }

    // Retrieve username from request body or query.
    const username = req.body.username || req.query.username;
    if (!username) {
      return this.error(new Error("Username is required."));
    }

    try {
      if (req.method === "GET") {
        // Challenge phase
        if (mode === "register") {
          const challenge = await this.registerChallenge(req, username);
          return this.success(challenge);
        } else if (mode === "login") {
          const challenge = await this.loginChallenge(req, username);
          return this.success(challenge);
        }
      } else if (req.method === "POST") {
        // Callback phase – expect credential in req.body.credential
        const credential = req.body.credential;
        if (!credential) {
          return this.error(
            new Error("Credential is required in the request body."),
          );
        }
        if (mode === "register") {
          const result = await this.registerCallback(req, username, credential);
          return this.success(result);
        } else if (mode === "login") {
          const result = await this.loginCallback(req, username, credential);
          return this.success(result);
        }
      } else {
        return this.error(new Error("Unsupported HTTP method."));
      }
    } catch (err: any) {
      return this.error(err);
    }
  }
}
