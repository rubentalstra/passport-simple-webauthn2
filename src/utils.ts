export const bufferToBase64URL = (buffer: any): string =>
  Buffer.from(buffer).toString("base64url");

export const serializeAuthenticationOptions = (options: any) => ({
  ...options,
  challenge: bufferToBase64URL(options.challenge),
});

export const serializeRegistrationOptions = (options: any) => ({
  ...options,
  challenge: bufferToBase64URL(options.challenge),
});
