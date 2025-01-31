export type Base64URLString = string;

/**
 * Converts an ArrayBuffer to a Base64URL-encoded string.
 * @param buffer - The ArrayBuffer to convert.
 * @returns A Base64URL-encoded string.
 */
export function bufferToBase64URL(buffer: Base64URLString): Base64URLString {
  return Buffer.from(buffer).toString("base64url");
}

export const serializeAuthenticationOptions = (
  options: Record<string, any>,
): Record<string, unknown> => ({
  ...options,
  challenge: bufferToBase64URL(options.challenge),
});

export const serializeRegistrationOptions = (
  options: Record<string, any>,
): Record<string, unknown> => ({
  ...options,
  challenge: bufferToBase64URL(options.challenge),
});
