import type { Identity } from "@dfinity/agent";

const DEFAULT_CLIENT_ID = "LocalClient";
const DEFAULT_SCOPE = "default offline_access";

type ChallengeResponse = {
  challenge: string;
  expires_in: number;
};

type RawTokenResponse = {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  scope?: string;
  expires_in?: number;
};

export type TokenResponse = {
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  scope?: string;
  issuedAt: Date;
  expiresAt?: Date;
  raw: RawTokenResponse;
};

const API_ORIGIN =
  import.meta.env.VITE_API_ORIGIN ?? "http://localhost:8000";

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function base64UrlToUint8Array(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - (normalized.length % 4)) % 4);
  const base64 = normalized + padding;
  const raw = typeof atob === "function" ? atob(base64) : Buffer.from(base64, "base64").toString("binary");
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    output[i] = raw.charCodeAt(i);
  }
  return output;
}

async function fetchChallenge(apiOrigin: string): Promise<ChallengeResponse> {
  const response = await fetch(`${apiOrigin}/auth/challenge`, {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to obtain challenge (${response.status})`);
  }

  return response.json();
}

async function buildInternetIdentityPayload(
  identity: Identity,
  challenge: ChallengeResponse,
): Promise<Record<string, string>> {
  const challengeBytes = base64UrlToUint8Array(challenge.challenge);
  const rawChallenge = challengeBytes.buffer.slice(
    challengeBytes.byteOffset,
    challengeBytes.byteOffset + challengeBytes.byteLength,
  );
  const signatureBytes = new Uint8Array(await (identity as any).sign(rawChallenge));
  const publicKeyDer = identity.getPublicKey().toDer();
  const publicKeyBytes = new Uint8Array(
    publicKeyDer.slice(0, publicKeyDer.byteLength) as ArrayBuffer,
  );

  const delegation = (identity as any).getDelegation?.();
  if (!delegation || typeof delegation.toJSON !== "function") {
    throw new Error("Active identity is missing delegation chain information");
  }

  return {
    ii_challenge: challenge.challenge,
    ii_signature: toHex(signatureBytes),
    ii_public_key: toHex(publicKeyBytes),
    ii_delegations: JSON.stringify(delegation.toJSON()),
  };
}

function parseTokenResponse(raw: RawTokenResponse): TokenResponse {
  const issuedAt = new Date();
  const expiresAt =
    typeof raw.expires_in === "number"
      ? new Date(issuedAt.getTime() + raw.expires_in * 1000)
      : undefined;

  return {
    accessToken: raw.access_token,
    refreshToken: raw.refresh_token,
    tokenType: raw.token_type,
    scope: raw.scope,
    issuedAt,
    expiresAt,
    raw,
  };
}

async function postTokenRequest(
  params: URLSearchParams,
  apiOrigin: string,
): Promise<TokenResponse> {
  const response = await fetch(`${apiOrigin}/auth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: params.toString(),
  });

  if (!response.ok) {
    let message = `Token endpoint returned ${response.status}`;
    try {
      const errorBody = await response.json();
      if (typeof errorBody.error_description === "string") {
        message = errorBody.error_description;
      } else if (typeof errorBody.error === "string") {
        message = errorBody.error;
      }
    } catch {
      // ignore parsing errors
    }
    throw new Error(message);
  }

  const data: RawTokenResponse = await response.json();
  if (!data.access_token || !data.token_type) {
    throw new Error("Token response is missing required fields");
  }

  return parseTokenResponse(data);
}

export async function obtainTokens(
  identity: Identity | undefined,
  options?: {
    apiOrigin?: string;
    clientId?: string;
    scope?: string;
  },
): Promise<TokenResponse> {
  if (!identity) {
    throw new Error("Internet Identity session is not available");
  }

  const apiOrigin = options?.apiOrigin ?? API_ORIGIN;
  const challenge = await fetchChallenge(apiOrigin);
  const iiPayload = await buildInternetIdentityPayload(identity, challenge);

  const params = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: options?.clientId ?? DEFAULT_CLIENT_ID,
    scope: options?.scope ?? DEFAULT_SCOPE,
    ...iiPayload,
  });

  return postTokenRequest(params, apiOrigin);
}

export async function refreshAccessToken(
  refreshToken: string,
  options?: {
    apiOrigin?: string;
    clientId?: string;
    scope?: string;
  },
): Promise<TokenResponse> {
  if (!refreshToken) {
    throw new Error("Missing refresh token");
  }

  const apiOrigin = options?.apiOrigin ?? API_ORIGIN;
  const params = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: refreshToken,
    client_id: options?.clientId ?? DEFAULT_CLIENT_ID,
  });

  if (options?.scope) {
    params.set("scope", options.scope);
  }

  return postTokenRequest(params, apiOrigin);
}
function detectP256Point(bytes: Uint8Array) {
  const rest = bytes.subarray(21);
  const prefix = rest[0];
  const x = rest.subarray(1, 22);
  const y = rest.subarray(22);
  console.log('prefix', prefix.toString(16), 'x', Buffer.from(x).toString('hex'), 'y', Buffer.from(y).toString('hex'));
}

const pk = new Uint8Array(Buffer.from('303c300c060a2b0601040183b8430102032c000affffffffff9000010101fc3fed47a82ee71224f2861b0d36ab05a9dbf43ca8a7339bee29c939187c136e', 'hex'));
detectP256Point(pk);
