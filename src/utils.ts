export const bufferToBase64URL = (buffer: any): string =>
  Buffer.from(buffer).toString("base64url");

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
