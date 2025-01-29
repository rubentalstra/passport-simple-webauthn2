import { Strategy as PassportStrategy } from "passport-strategy";
import { verifyAuthentication } from "./authentication";
import type { Request } from "express";
import type {
  VerifiedAuthenticationResponse,
  WebAuthnCredential,
} from "@simplewebauthn/server";

export interface SimpleWebAuthnStrategyOptions {
  getUser: (
    req: Request,
    id: Uint8Array,
  ) => Promise<{ id: Uint8Array; credentials: WebAuthnCredential[] } | null>;
}

export class SimpleWebAuthnStrategy extends PassportStrategy {
  name = "simple-webauthn";
  private options: SimpleWebAuthnStrategyOptions;

  constructor(options: SimpleWebAuthnStrategyOptions) {
    super();
    this.options = options;
  }

  async authenticate(req: Request): Promise<void> {
    try {
      const { userId, response } = req.body;
      if (!userId || !response) {
        return this.fail("Missing userId or response", 400);
      }

      const user = await this.options.getUser(
        req,
        Buffer.from(userId, "base64url"),
      );
      if (!user) return this.fail("User not found", 404);

      const verification: VerifiedAuthenticationResponse =
        await verifyAuthentication(req, user, response);

      if (!verification.verified) return this.fail("Verification failed", 403);

      return this.success(user);
    } catch (error) {
      if (error instanceof Error) {
        return this.error(error);
      }
      return this.error(new Error("An unknown error occurred"));
    }
  }
}
