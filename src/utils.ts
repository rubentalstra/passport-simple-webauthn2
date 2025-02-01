export function bufferToBase64URL(
  buffer: Buffer | ArrayBuffer | string,
): string {
  if (typeof buffer === "string") return buffer;
  return Buffer.from(buffer as any).toString("base64url");
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
