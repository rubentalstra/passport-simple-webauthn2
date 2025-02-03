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
  getExpectedOrigin,
  normalizePublicKey,
  serializeOptions,
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

  /**
   * Retrieve a user by email or id.
   */
  private async getUser(
    identifier: string,
    byID = false,
  ): Promise<WebAuthnUser | undefined> {
    return this.userStore.get(identifier, byID);
  }

  /**
   * Retrieve the user if exists; otherwise, create and save a new user.
   */
  private async getOrCreateUser(email: string): Promise<WebAuthnUser> {
    let user = await this.getUser(email);
    if (!user) {
      this.debugLog(`User not found. Creating new user for email: ${email}`);
      user = { email, passkeys: [] } as WebAuthnUser;
      user = await this.userStore.save(user);
      if (!user.id) {
        throw new Error("User creation failed: no id returned from the stores");
      }
      this.debugLog(`New user created with id: ${user.id}`);
    } else {
      this.debugLog(`User found with id: ${user.id}`);
    }
    return user;
  }

  // ---------------------
  // Registration Flow
  // ---------------------

  async registerChallenge(
    req: Request,
    email: string,
  ): Promise<Record<string, unknown>> {
    this.debugLog(`registerChallenge called for email: ${email}`);
    if (!email) throw new Error("Email required");

    const user = await this.getOrCreateUser(email);
    const userId: string = user.id!;
    this.debugLog("Generating registration options");

    const options = await generateRegistrationOptions({
      rpName: this.rpName || "WebAuthn Demo",
      rpID: this.rpID || "localhost",
      userID: Buffer.from(userId, "utf-8"),
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

    const challengeStr = bufferToBase64URL(options.challenge);
    await this.challengeStore.save(userId, challengeStr);
    this.logger.info(
      `Registration challenge generated for user ${user.email} (id: ${userId})`,
    );

    return serializeOptions(options);
  }

  async registerCallback(
    req: Request,
    email: string,
    credential: RegistrationResponseJSON,
  ): Promise<WebAuthnUser> {
    this.debugLog(`registerCallback called for email: ${email}`);
    const user = await this.getUser(email);
    if (!user || !user.id) throw new Error("User not found or id is missing");

    const challenge = await this.challengeStore.get(user.id);
    if (!challenge) throw new Error("Challenge not found");

    try {
      this.debugLog("Verifying registration response", credential);
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin: getExpectedOrigin(this.rpID),
        expectedRPID: this.rpID || "localhost",
        requireUserVerification: true,
      });
      await this.challengeStore.delete(user.id);

      if (!verification.verified || !verification.registrationInfo) {
        this.logger.error("Registration verification failed");
        throw new Error("Verification failed");
      }

      const { publicKey, id, counter, transports } =
        verification.registrationInfo.credential;
      this.debugLog("Storing new passkey", { id, counter, transports });

      const publicKeyBuffer = normalizePublicKey(publicKey);
      const newPasskey = {
        id,
        publicKey: publicKeyBuffer,
        counter,
        transports,
      };

      user.passkeys.push(newPasskey);
      const updatedUser = await this.userStore.save(user);
      this.debugLog("User updated with new passkey", updatedUser);
      return updatedUser;
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Registration failed";
      this.logger.error(`Error during registration callback: ${errorMsg}`);
      throw new Error(errorMsg);
    }
  }

  // ---------------------
  // Login Flow
  // ---------------------

  async loginChallenge(
    req: Request,
    email: string,
  ): Promise<Record<string, unknown>> {
    this.debugLog(`loginChallenge called for email: ${email}`);
    const user = await this.getUser(email);
    if (!user || !user.id) throw new Error("User not found or id is missing");

    // Filter for platform authenticators.
    const platformCredentials = user.passkeys.filter((cred) =>
      cred.transports?.includes("internal"),
    );

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

    const challengeStr = bufferToBase64URL(options.challenge);
    await this.challengeStore.save(user.id, challengeStr);
    this.logger.info(
      `Login challenge generated for user ${user.email} (id: ${user.id})`,
    );
    return serializeOptions(options);
  }

  async loginCallback(
    req: Request,
    email: string,
    credential: AuthenticationResponseJSON,
  ): Promise<WebAuthnUser> {
    this.debugLog(`loginCallback called for email: ${email}`);
    const user = await this.getUser(email);
    if (!user || !user.id) throw new Error("User not found or id is missing");

    const challenge = await this.challengeStore.get(user.id);
    if (!challenge) throw new Error("Challenge not found");

    const passkey = user.passkeys.find((p) => p.id === credential.id);
    if (!passkey) {
      this.logger.error(
        `Passkey not found for credential id: ${credential.id}`,
      );
      throw new Error("Passkey not found");
    }

    try {
      const storedPublicKey = normalizePublicKey(passkey.publicKey);
      this.debugLog("Verifying authentication response", credential);
      const verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: challenge,
        expectedOrigin: getExpectedOrigin(this.rpID),
        expectedRPID: this.rpID,
        credential: {
          id: passkey.id,
          publicKey: storedPublicKey,
          counter: passkey.counter,
          transports: passkey.transports,
        },
        requireUserVerification: true,
      });
      await this.challengeStore.delete(user.id);

      if (!verification.verified) {
        this.logger.error("Authentication verification failed");
        throw new Error("Verification failed");
      }

      passkey.counter = verification.authenticationInfo.newCounter;
      const updatedUser = await this.userStore.save(user);
      this.debugLog("User updated with new counter", updatedUser);
      return updatedUser;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : "Login failed";
      this.logger.error(`Error during login callback: ${errorMsg}`);
      throw new Error(errorMsg);
    }
  }

  // ---------------------
  // Passport Strategy Integration
  // ---------------------

  /**
   * Fully integrated authenticate() method.
   * Infers the mode (register or login) from the request path.
   */
  async authenticate(req: Request, _options?: any): Promise<void> {
    try {
      const mode = this.determineMode(req.path);
      const email = req.body.email || req.query.email;
      if (!email) throw new Error("Email is required.");
      const result = await this.handleRequestByMethod(req, mode, email);
      this.success(result);
    } catch (err: any) {
      this.error(err);
    }
  }

  /**
   * Determines the mode based on the request path.
   */
  private determineMode(path: string): "register" | "login" {
    const lowerPath = path.toLowerCase();
    if (lowerPath.includes("register")) return "register";
    if (lowerPath.includes("login")) return "login";
    throw new Error(
      "Could not infer mode. Please ensure the URL contains either register or login.",
    );
  }

  /**
   * Delegates the request based on HTTP method and mode.
   */
  private async handleRequestByMethod(
    req: Request,
    mode: "register" | "login",
    email: string,
  ): Promise<any> {
    if (req.method === "GET") {
      return mode === "register"
        ? this.registerChallenge(req, email)
        : this.loginChallenge(req, email);
    } else if (req.method === "POST") {
      const credential = req.body.credential;
      if (!credential)
        throw new Error("Credential is required in the request body.");
      return mode === "register"
        ? this.registerCallback(req, email, credential)
        : this.loginCallback(req, email, credential);
    } else {
      throw new Error("Unsupported HTTP method.");
    }
  }
}
