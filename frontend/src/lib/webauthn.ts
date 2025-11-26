export const textEncoder = new TextEncoder();

export function bufferToBase64url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlToBuffer(value: string): ArrayBuffer {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const base64 = (value + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  const buffer = new ArrayBuffer(raw.length);
  const view = new Uint8Array(buffer);
  for (let i = 0; i < raw.length; i += 1) {
    view[i] = raw.charCodeAt(i);
  }
  return buffer;
}

export function stringToBuffer(value: string): ArrayBuffer {
  return textEncoder.encode(value).buffer;
}

export type WebAuthnCredentialJSON = {
  id: string;
  rawId: string;
  type: string;
  response: Record<string, unknown>;
};

export function serializeAttestation(credential: PublicKeyCredential): WebAuthnCredentialJSON {
  const response =
    credential.response as AuthenticatorAttestationResponse &
      Partial<{
        publicKey: ArrayBuffer | string;
        publicKeyAlgorithm: number;
        credentialId: string;
      }>;

  const enriched: Record<string, unknown> = {
    clientDataJSON: bufferToBase64url(response.clientDataJSON),
    attestationObject: bufferToBase64url(response.attestationObject),
  };

  if (response.publicKey) {
    enriched.publicKey =
      typeof response.publicKey === "string"
        ? response.publicKey
        : bufferToBase64url(response.publicKey);
  }
  if (typeof response.publicKeyAlgorithm === "number") {
    enriched.publicKeyAlgorithm = response.publicKeyAlgorithm;
  }
  if (response.credentialId) {
    enriched.credentialId = response.credentialId;
  }

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: enriched,
  };
}

export function serializeAssertion(credential: PublicKeyCredential): WebAuthnCredentialJSON {
  const response =
    credential.response as AuthenticatorAssertionResponse &
      Partial<{ signature: ArrayBuffer | string; authenticatorData: ArrayBuffer | string; clientDataJSON: ArrayBuffer | string }>;

  const encodeField = (value: ArrayBuffer | string | undefined) => {
    if (!value) return undefined;
    if (typeof value === "string") return value;
    return bufferToBase64url(value);
  };

  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: encodeField(response.clientDataJSON)!,
      authenticatorData: encodeField(response.authenticatorData)!,
      signature: encodeField(response.signature)!,
      userHandle:
        typeof response.userHandle === "string"
          ? response.userHandle
          : response.userHandle
            ? bufferToBase64url(response.userHandle)
            : undefined,
    },
  };
}
