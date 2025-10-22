TODO:

- Use https://docs.rs/ic-certification/

- Specify proxy's identity.

- Heavy `Vec` copy operations may hinder performance.

- Make responses streaming (impossible due to caching?)

- Implement file-persistency for in-memory DB. Also, save on `SIG{INT,TERM}`.

- Redis storage support.

- Incrementing nonce to avoid upstream request replay attack.

- If the proxy is directed to its own URL, will this work as a DoS attack?

- Test: `add_per_host`, `remove_per_host`.

- Add `x-nonce`?

- Test that access to keys stored in the DB is secure.

- Use `r2d2`.

- Reduce use of `anyhow`/`bail`.