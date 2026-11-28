// 浏览器 WebAuthn Passkey 工具：Base64URL 与 ArrayBuffer 互转及凭证序列化

export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator.credentials !== 'undefined'
  );
}

export function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = window.atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes.buffer;
}

export function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface RawCredentialDescriptor {
  id: string;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransport[];
}

export async function createPasskeyCredential(optionsPayload: {
  publicKey: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  if (!isWebAuthnSupported()) {
    throw new Error('当前浏览器不支持通行密钥（WebAuthn）');
  }
  const pk = optionsPayload.publicKey as Record<string, unknown>;
  const userObj = pk.user as { id: string; name: string; displayName: string };
  const excludeList = (pk.excludeCredentials as RawCredentialDescriptor[] | undefined) || [];

  const publicKey: PublicKeyCredentialCreationOptions = {
    ...(pk as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64UrlToBuffer(pk.challenge as string),
    user: {
      ...userObj,
      id: base64UrlToBuffer(userObj.id),
    },
    excludeCredentials: excludeList.map((c) => ({
      ...c,
      id: base64UrlToBuffer(c.id),
    })),
  };

  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) {
    throw new Error('已取消通行密钥创建');
  }
  const response = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      attestationObject: bufferToBase64Url(response.attestationObject),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      transports: typeof response.getTransports === 'function' ? response.getTransports() : undefined,
    },
  };
}

export async function getPasskeyAssertion(optionsPayload: {
  publicKey: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  if (!isWebAuthnSupported()) {
    throw new Error('当前浏览器不支持通行密钥（WebAuthn）');
  }
  const pk = optionsPayload.publicKey as Record<string, unknown>;
  const allowList = (pk.allowCredentials as RawCredentialDescriptor[] | undefined) || [];

  const publicKey: PublicKeyCredentialRequestOptions = {
    ...(pk as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64UrlToBuffer(pk.challenge as string),
    allowCredentials:
      allowList.length > 0
        ? allowList.map((c) => ({
            ...c,
            id: base64UrlToBuffer(c.id),
          }))
        : undefined,
  };

  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) {
    throw new Error('已取消通行密钥验证');
  }
  const response = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    },
  };
}
