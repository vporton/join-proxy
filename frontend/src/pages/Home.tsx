import { useInternetIdentity } from "ic-use-internet-identity";
import { useMemo } from "react";

export function Home() {
    const {identity, isLoginSuccess} = useInternetIdentity();
    const userPrincipal = useMemo(() => identity?.getPrincipal(), [identity]);
    return (
        <>
            {/* TODO: "copy principal" button */}
            {isLoginSuccess && <>
                <p>Your user principal is <code>{userPrincipal?.toText()}</code>.</p>
                <p>To set or read your canister settings, create a canister with a function <code>isJoinProxyUser</code>{" "}
                (with a <code>principal</code> as its sole argument) that returns <code>true</code> for your user principal{" "}
                (and <code>false</code> or trap for third-party users).</p>
                <p>Be warned that if you return an incorrect <code>true</code> value from <code>isJoinProxyUser</code>,{" "}
                your settings (such as secret keys in added HTTP headers) will be both settable and readable by the user{" "}
                having <code>true</code> value.</p>
            </>}
        </>
    );
}