// utils.ts

export type Base64URLString = string;

export function bufferToBase64URL(
  input: ArrayBuffer | Buffer | string,
): string {
  if (typeof input === "string") {
    return input; // assume it's already a base64url string
  }
  return Buffer.from(input).toString("base64url");
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
