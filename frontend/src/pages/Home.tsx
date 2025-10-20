import { useInternetIdentity } from "ic-use-internet-identity";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Button } from "react-bootstrap";

import { obtainTokens, refreshAccessToken, type TokenResponse } from "../api/auth";

export function Home() {
  const { identity, isLoginSuccess } = useInternetIdentity();
  const userPrincipal = useMemo(() => identity?.getPrincipal(), [identity]);
  const [tokens, setTokens] = useState<TokenResponse | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  useEffect(() => {
    if (!identity) {
      setTokens(null);
      setErrorMessage(null);
    }
  }, [identity]);

  const handleObtainTokens = useCallback(async () => {
    if (!identity) {
      return;
    }

    setIsBusy(true);
    setErrorMessage(null);
    try {
      const result = await obtainTokens(identity);
      setTokens(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setErrorMessage(message);
    } finally {
      setIsBusy(false);
    }
  }, [identity]);

  const handleRefresh = useCallback(async () => {
    if (!tokens?.refreshToken) {
      return;
    }

    setIsBusy(true);
    setErrorMessage(null);
    try {
      const result = await refreshAccessToken(tokens.refreshToken);
      setTokens(result);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setErrorMessage(message);
    } finally {
      setIsBusy(false);
    }
  }, [tokens]);

  return (
    <>
      {/* TODO: "copy principal" button */}
      {isLoginSuccess && (
        <>
        <p>{JSON.stringify(tokens)}</p>
          <p>
            Your user principal is <code>{userPrincipal?.toText()}</code>.
          </p>
          <p>
            To set or read your canister settings, create a canister with a function <code>isJoinProxyUser</code>{" "}
            (with a <code>principal</code> as its sole argument) that returns <code>true</code> for your user principal{" "}
            (and <code>false</code> or trap for third-party users).
          </p>
          <p>
            Be warned that if you return an incorrect <code>true</code> value from <code>isJoinProxyUser</code>, your settings (such as secret keys in added HTTP headers)
            will be both settable and readable by the user having <code>true</code> value.
          </p>
          <p>
            FIXME: Check whether this is secure for looking into others' secrets, using a specifically crafted canister.
          </p>
          <div className="d-flex gap-2 flex-wrap">
            <Button disabled={!identity || isBusy} onClick={handleObtainTokens} variant="primary">
              {isBusy ? "Working..." : tokens ? "Reissue Access Token" : "Obtain Access Token"}
            </Button>
            {tokens?.refreshToken && (
              <Button disabled={isBusy} onClick={handleRefresh} variant="secondary">
                Refresh Using Stored Token
              </Button>
            )}
          </div>
          {errorMessage && <p className="text-danger mt-3">{errorMessage}</p>}
          {tokens && (
            <div className="mt-3">
              <p>
                <strong>Access Token:</strong> <code>{tokens.accessToken}</code>
              </p>
              {tokens.refreshToken && (
                <p>
                  <strong>Refresh Token:</strong> <code>{tokens.refreshToken}</code>
                </p>
              )}
              <p>
                <strong>Token Type:</strong> {tokens.tokenType}
              </p>
              {tokens.scope && (
                <p>
                  <strong>Scope:</strong> {tokens.scope}
                </p>
              )}
              {tokens.expiresAt && (
                <p>
                  <strong>Expires At:</strong> {tokens.expiresAt.toLocaleString()}
                </p>
              )}
            </div>
          )}
        </>
      )}
    </>
  );
}
