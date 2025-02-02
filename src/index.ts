/**
 * Passport Strategy that implements "Web Authn (PassKeys)"
 */
import { Strategy as PassportStrategy } from "passport-strategy";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { Request } from "express";
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
    email: string,
  ): Promise<Record<string, unknown>> {
    this.debugLog(`registerChallenge called for email: ${email}`);
    if (!email) throw new Error("Email required");

    let user = await this.getUser(email);
    if (!user) {
      this.debugLog(`User not found. Creating new user for email: ${email}`);
      // Create a new user object without an id, so that the DB can generate one.
      user = { email, passkeys: [] } as WebAuthnUser;
      user = await this.userStore.save(user);
      // Ensure that an id was generated.
      if (!user.id) {
        throw new Error("User creation failed: no id returned from the stores");
      }
      this.debugLog(`New user created with id: ${user.id}`);
    } else {
      this.debugLog(`User found with id: ${user.id}`);
    }

    // At this point, we know that user.id is defined.
    const userId: string = user.id!;
    this.debugLog("Generating registration options");
    const options = await generateRegistrationOptions({
      rpName: this.rpName || "WebAuthn Demo",
      rpID: this.rpID || "localhost",
      userID: Buffer.from(userId, "utf-8"),
      // Use email as the userName for registration
      userName: user.email,
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
    await this.challengeStore.save(userId, challengeStr);
    this.debugLog(`Challenge saved for user id ${userId}: ${challengeStr}`);

    const serializedOptions = serializeRegistrationOptions(options);
    this.debugLog("Serialized registration options", serializedOptions);

    this.logger.info(
      `Registration challenge generated for user ${user.email} (id: ${userId})`,
    );

    return serializedOptions;
  }

  async registerCallback(
    req: Request,
    email: string,
    credential: RegistrationResponseJSON,
  ): Promise<WebAuthnUser> {
    this.debugLog(`registerCallback called for email: ${email}`);
    const user = await this.getUser(email);
    if (!user) {
      this.logger.error(`User not found for email: ${email}`);
      throw new Error("User not found");
    }
    if (!user.id) {
      throw new Error("User id is missing");
    }
    this.debugLog(`User found with id: ${user.id}`);

    const challenge = await this.challengeStore.get(user.id);
    if (!challenge) {
      this.logger.error(`Challenge not found for user id: ${user.id}`);
      throw new Error("Challenge not found");
    }
    this.debugLog(`Challenge retrieved for user id ${user.id}: ${challenge}`);

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

      await this.challengeStore.delete(user.id);
      this.debugLog(`Challenge deleted for user id ${user.id}`);

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
      const updatedUser = await this.userStore.save(user);
      this.debugLog("User updated with new passkey", updatedUser);

      return updatedUser;
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
    email: string,
  ): Promise<Record<string, unknown>> {
    this.debugLog(`loginChallenge called for email: ${email}`);
    const user = await this.getUser(email);
    if (!user) {
      this.logger.error(`User not found for email: ${email}`);
      throw new Error("User not found");
    }
    if (!user.id) {
      throw new Error("User id is missing");
    }
    this.debugLog(`User found with id: ${user.id}`);

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
              id: cred.id,
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
    await this.challengeStore.save(user.id, challengeStr);
    this.debugLog(`Challenge saved for user id ${user.id}: ${challengeStr}`);

    const serializedOptions = serializeAuthenticationOptions(options);
    this.debugLog("Serialized authentication options", serializedOptions);

    this.logger.info(
      `Login challenge generated for user ${user.email} (id: ${user.id})`,
    );
    return serializedOptions;
  }

  async loginCallback(
    req: Request,
    email: string,
    credential: AuthenticationResponseJSON,
  ): Promise<WebAuthnUser> {
    this.debugLog(`loginCallback called for email: ${email}`);
    const user = await this.getUser(email);
    if (!user) {
      this.logger.error(`User not found for email: ${email}`);
      throw new Error("User not found");
    }
    if (!user.id) {
      throw new Error("User id is missing");
    }
    this.debugLog(`User found with id: ${user.id}`);

    const challenge = await this.challengeStore.get(user.id);
    if (!challenge) {
      this.logger.error(`Challenge not found for user id: ${user.id}`);
      throw new Error("Challenge not found");
    }
    this.debugLog(`Challenge retrieved for user id ${user.id}: ${challenge}`);

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

      await this.challengeStore.delete(user.id);
      this.debugLog(`Challenge deleted for user id ${user.id}`);

      if (!verification.verified) {
        this.logger.error("Authentication verification failed");
        this.debugLog("Authentication verification failed");
        throw new Error("Verification failed");
      }

      // Update the counter on the passkey and save the user
      passkey.counter = verification.authenticationInfo.newCounter;
      const updatedUser = await this.userStore.save(user);
      this.debugLog("User updated with new counter", updatedUser);

      return updatedUser;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Login failed";
      this.logger.error(`Error during login callback: ${errorMsg}`);
      this.debugLog(`Error during login callback: ${errorMsg}`);
      throw new Error(errorMsg);
    }
  }

  /**
   * Fully integrated authenticate() method.
   * It infers the mode (register or login) from the request path.
   */
  async authenticate(req: Request, _options?: any): Promise<void> {
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

    // Use email for identification (instead of username)
    const email = req.body.email || req.query.email;
    if (!email) {
      return this.error(new Error("Email is required."));
    }

    try {
      if (req.method === "GET") {
        if (mode === "register") {
          const challenge = await this.registerChallenge(req, email);
          return this.success(challenge);
        } else if (mode === "login") {
          const challenge = await this.loginChallenge(req, email);
          return this.success(challenge);
        }
      } else if (req.method === "POST") {
        const credential = req.body.credential;
        if (!credential) {
          return this.error(
            new Error("Credential is required in the request body."),
          );
        }
        if (mode === "register") {
          const result = await this.registerCallback(req, email, credential);
          return this.success(result);
        } else if (mode === "login") {
          const result = await this.loginCallback(req, email, credential);
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
