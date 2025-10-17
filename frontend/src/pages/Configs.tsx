import { useState } from "react";

export function Configs() {
    const [configs, setConfigs] = useState<{uid: string, name: string}[] | undefined>();
    return (
        <>
            {configs !== undefined ? <ul>
                {configs.map(c => <a href={`/config/edit/${c.uid}`}>{c.name}</a>)}
            </ul> : <p>Loading...</p>}
        </>
    );
}