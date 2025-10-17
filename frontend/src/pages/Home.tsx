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
                (with a `principal` as its sole argument) that returns <code>True</code> for your user principal{" "}
                (and <code>False</code> for third-party users).</p>
            </>}
        </>
    );
}