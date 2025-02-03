/* ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
   UTILITY
––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––– */

export function bufferToBase64URL(
  buffer: Buffer | ArrayBuffer | string,
): string {
  if (typeof buffer === "string") return buffer;
  return Buffer.from(buffer as any).toString("base64url");
}

/**
 * Unified options serialization helper.
 */
export const serializeOptions = (
  options: Record<string, any>,
): Record<string, unknown> => ({
  ...options,
  challenge: bufferToBase64URL(options.challenge),
});

/**
 * Returns the expected origin based on the environment.
 */
export function getExpectedOrigin(rpID: string): string {
  return process.env.NODE_ENV === "development"
    ? `http://${rpID}`
    : `https://${rpID}`;
}

/**
 * Normalizes a public key to a Buffer.
 */
export function normalizePublicKey(publicKey: any): Buffer {
  return publicKey && publicKey.buffer
    ? Buffer.from(publicKey.buffer)
    : Buffer.from(publicKey);
}
