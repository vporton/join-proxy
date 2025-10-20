import type { Identity } from "@dfinity/agent";

const DEFAULT_CLIENT_ID = "LocalClient";
const DEFAULT_SCOPE = "default offline_access";

const P256_SPKI_PREFIX = new Uint8Array([
  0x30, 0x59,
  0x30, 0x13,
  0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
  0x03, 0x42, 0x00,
]);

const P256_MODULUS = BigInt(
  "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
);
const P256_B = BigInt(
  "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
);

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
  const raw =
    typeof atob === "function"
      ? atob(base64)
      : (globalThis.Buffer?.from(base64, "base64").toString("binary") ??
          (() => {
            throw new Error("Base64 decoding not available");
          })());
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
  const publicKeyBytes = extractPublicKeyBytes(identity);

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

function extractPublicKeyBytes(identity: Identity): Uint8Array {
  const publicKey = identity.getPublicKey();
  const rawCandidate = extractRawKey(publicKey);

  if (rawCandidate) {
    const uncompressed = normalizeUncompressedPoint(rawCandidate);
    if (uncompressed) {
      const spki = new Uint8Array(P256_SPKI_PREFIX.length + uncompressed.length);
      spki.set(P256_SPKI_PREFIX, 0);
      spki.set(uncompressed, P256_SPKI_PREFIX.length);
      return spki;
    }
  }

  const der = publicKey.toDer();
  if (der instanceof ArrayBuffer) {
    return new Uint8Array(der);
  }
  return new Uint8Array(der.slice(0));
}

function extractRawKey(publicKey: any): Uint8Array | null {
  if (typeof publicKey.toRaw === "function") {
    return new Uint8Array(publicKey.toRaw());
  }
  if (publicKey.rawKey instanceof ArrayBuffer) {
    return new Uint8Array(publicKey.rawKey);
  }
  return null;
}

function normalizeUncompressedPoint(raw: Uint8Array): Uint8Array | null {
  if (raw.length === 65 && raw[0] === 0x04) {
    return raw;
  }

  if (raw.length === 64) {
    const extended = new Uint8Array(65);
    extended[0] = 0x04;
    extended.set(raw, 1);
    return extended;
  }

  if (raw.length === 33 && (raw[0] === 0x02 || raw[0] === 0x03)) {
    return decompressCompressedPoint(raw);
  }

  return null;
}

function decompressCompressedPoint(raw: Uint8Array): Uint8Array | null {
  const prefix = raw[0];
  const xBytes = raw.slice(1);

  const x = bytesToBigInt(xBytes);
  const rhs = mod(mod(x * x) * x + P256_B, P256_MODULUS);
  const y = modSqrt(rhs, P256_MODULUS);
  if (y === null) {
    return null;
  }

  const isOdd = (y & 1n) === 1n;
  let yAdjusted = y;
  if ((prefix === 0x03 && !isOdd) || (prefix === 0x02 && isOdd)) {
    yAdjusted = P256_MODULUS - y;
  }

  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(padStart(xBytes, 32), 1);
  uncompressed.set(bigIntTo32Bytes(yAdjusted), 33);
  return uncompressed;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = mod(base, modulus);
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) {
      result = mod(result * b, modulus);
    }
    b = mod(b * b, modulus);
    e >>= 1n;
  }
  return result;
}

function modSqrt(a: bigint, p: bigint): bigint | null {
  if (a === 0n) return 0n;
  if (p % 4n !== 3n) return null;
  const candidate = modPow(a, (p + 1n) / 4n, p);
  if (mod(candidate * candidate, p) === mod(a, p)) {
    return candidate;
  }
  const other = p - candidate;
  if (mod(other * other, p) === mod(a, p)) {
    return other;
  }
  return null;
}

function mod(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder < 0n ? remainder + modulus : remainder;
}

function reconstructTruncatedPoint(raw: Uint8Array): Uint8Array | null {
  const remainder = raw.slice(1);
  if (remainder.length % 2 !== 0) {
    return null;
  }

  const coordLen = remainder.length / 2;
  if (coordLen === 0 || coordLen > 32) {
    return null;
  }

  const xBytes = remainder.slice(0, coordLen);
  const yBytes = remainder.slice(coordLen);

  const xFull = bytesToBigInt(padStart(xBytes, 32));
  const modulus = 1n << BigInt(8 * yBytes.length);
  const residue = bytesToBigInt(yBytes);

  const rhs = mod(mod(xFull * xFull) * xFull + P256_B, P256_MODULUS);
  const sqrt = modSqrt(rhs, P256_MODULUS);
  if (sqrt === null) {
    return null;
  }

  const inverse = invertModPowerOfTwo(P256_MODULUS, 8 * yBytes.length);
  const possibilities = [
    reconcileRoot(sqrt, residue, modulus, inverse),
    reconcileRoot(P256_MODULUS - sqrt, residue, modulus, inverse),
  ].filter((value): value is bigint => value !== null);

  if (possibilities.length === 0) {
    return null;
  }

  const yFull = possibilities[0];
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(padStart(xBytes, 32), 1);
  uncompressed.set(bigIntTo32Bytes(yFull), 33);
  return uncompressed;
}

function reconcileRoot(
  root: bigint,
  residue: bigint,
  modulus: bigint,
  inverse: bigint,
): bigint | null {
  const currentResidue = mod(root, modulus);
  const diff = mod(residue - currentResidue, modulus);
  const t = mod(diff * inverse, modulus);
  const candidate = mod(root + P256_MODULUS * t, P256_MODULUS);
  return mod(candidate, modulus) === residue ? candidate : null;
}

function invertModPowerOfTwo(a: bigint, bits: number): bigint {
  let inverse = 1n;
  let modulus = 2n;
  for (let i = 1; i < bits; i += 1) {
    inverse = (inverse * (2n - a * inverse)) % modulus;
    modulus <<= 1n;
  }
  const mask = (1n << BigInt(bits)) - 1n;
  return inverse & mask;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = "";
  for (const byte of bytes) {
    hex += byte.toString(16).padStart(2, "0");
  }
  return BigInt(`0x${hex || "0"}`);
}

function padStart(bytes: Uint8Array, targetLength: number): Uint8Array {
  if (bytes.length >= targetLength) {
    return bytes;
  }
  const output = new Uint8Array(targetLength);
  output.set(bytes, targetLength - bytes.length);
  return output;
}

function bigIntTo32Bytes(value: bigint): Uint8Array {
  const hex = value.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
