import { useInternetIdentity } from "ic-use-internet-identity";
import { useMemo } from "react";

export function Home() {
    const {identity, isLoginSuccess} = useInternetIdentity();
    const userPrincipal = useMemo(() => identity?.getPrincipal(), [identity]);
    return (
        <>
            {/* TODO: copy principal button */}
            {isLoginSuccess && <>
                <p>Your user principal is <code>{userPrincipal?.toText()}</code>.</p>
                <p>To set your canister settings, create a canister with a function <code>isJoinProxyUser</code>{" "}
                (with a <code>principal</code> as its sole argument) that returns <code>true</code> for your user principal{" "}
                (and <code>false</code> or trap for third-party users).</p>
            </>}
        </>
    );
}