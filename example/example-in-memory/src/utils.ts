// utils.ts
import { Base64URLString } from './types';
import {AuthenticationResponseJSON, RegistrationResponseJSON} from "@simplewebauthn/server";

/**
 * Converts an ArrayBuffer to a Base64URL-encoded string.
 * @param buffer - The ArrayBuffer to convert.
 * @returns A Base64URL-encoded string.
 */
export function bufferToBase64URL(buffer: Base64URLString): Base64URLString {
    return Buffer.from(buffer).toString('base64url');
}

/**
 * Converts a Base64URL-encoded string to an ArrayBuffer.
 * @param base64url - The Base64URL-encoded string to convert.
 * @returns An ArrayBuffer.
 */
export function base64URLToBuffer(base64url: Base64URLString): ArrayBuffer {
    return Buffer.from(base64url, 'base64url').buffer;
}

/**
 * Serializes PublicKeyCredentialCreationOptions to send to the client.
 * Converts Buffer and ArrayBuffer fields to Base64URL strings.
 */
export function serializeRegistrationOptions(options: any) {
    return {
        ...options,
        challenge: bufferToBase64URL(options.challenge),
        user: {
            ...options.user,
            id: bufferToBase64URL(options.user.id),
        },
        excludeCredentials: options.excludeCredentials?.map((cred: any) => ({
            ...cred,
            id: bufferToBase64URL(cred.id),
        })),
    };
}


/**
 * Serializes PublicKeyCredentialRequestOptions to send to the client.
 * Converts Buffer and ArrayBuffer fields to Base64URL strings.
 */
export function serializeAuthenticationOptions(options: any) {
    return {
        ...options,
        challenge: bufferToBase64URL(options.challenge),
        allowCredentials: options.allowCredentials?.map((cred: any) => ({
            ...cred,
            id: bufferToBase64URL(cred.id),
        })),
    };
}

/**
 * Deserializes AuthenticationResponseJSON received from the client.
 * Converts Base64URL strings back to Buffer.
 */
export function deserializeAuthenticationResponse(credential: AuthenticationResponseJSON) {
    return {
        id: credential.id,
        rawId: base64URLToBuffer(credential.rawId as string),
        response: {
            authenticatorData: base64URLToBuffer(credential.response.authenticatorData as string),
            clientDataJSON: base64URLToBuffer(credential.response.clientDataJSON as string),
            signature: base64URLToBuffer(credential.response.signature as string),
            userHandle: credential.response.userHandle
                ? base64URLToBuffer(credential.response.userHandle as string)
                : null,
        },
        type: credential.type,
        clientExtensionResults: credential.clientExtensionResults,
    };
}