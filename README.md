# Join Proxy

WARNING: It is a beta version that you can use, but no warranty.

Also be warned that there are some security drawbacks, that one can use to drain money
from your cycles wallet (however, it is hard for a hacker, so you probably shouldn't worry).

It has been tested positively in a real dapp ([Zon](https://docs.zoncircle.com)) to channel AI
requests to both OpenAI and Pinecone.

## What it does

This is a proxy that intentionally delivers outdated data (ignoring, for instance, `Cache-Control:` header).
It is intended mainly to direct IC outcalls to this proxy,
in order for do one, not 13 or more requests to an upstream in a single outcall.
Thus you, for example, pay 13x less for OpenAI tokens, if IC is connected to it through
this proxy. It also helps against reaching API throttling.

It has special support for [Internet Computer](https://internetcomputer.org/), namely it can ask
IC to authenticate every request. This makes a malicious replica unable for example to steal your OpenAI tokens.
And my solution is far less expensive than using tECDSA would be.

It caches requests in memory. Optional Redis backend and more performance optimizations will be added after I get a grant.
(Code for switching alternating between several backends is already present.)

## Welcome

First run `git submodule init`, because due to MOPS package manager non-support for packages in a subdirectory
we need to make `motoko/` a separate repository.

To get started, you might want to explore the project directory structure and the default configuration file.

If you want to start working on your project right away, you might want to try the following commands:

```bash
cd joining_proxy/
cargo build --release
cargo run --release
```

## Configuration

The proxy app is called as:

```bash
join-proxy [--config <TOML> | -c <TOML>]
```

where `<TOML>` is a [TOML](https://toml.io) file with configuration. By default the file `config.toml` from current directory is used.

An example of `config.toml`:

```toml
# Simple Bearer authentication. On IC platform you should use callback authentication instead.
# If you omit this entry, no Bearer authentication is done.
our_secret = "<KEY>"

[serve]
# The host and port to attach:
host = "localhost" # "localhost" by default
port = 8080 # 8080 by default
https = false # use HTTPS (false by default)

# HTTPS certificate:
cert_file = "..."
key_file = "..."

# If you omit this section, no authorization by callbacks is done.
# WARNING: In this case your proxy is eligible to unauthorized connections, such as stealing your OpenAI tokens.
[callback]
ic_local = false # if to use a local testnet, DON'T SET THIS TO TRUE IN PRODUCTION
ic_url = "https://localhost:8000" # URL to connect to IC (for authorization), the default value is determined by `ic_local`
canister = "a3shf-5eaaa-aaaaa-qaafa-cai" # the principal of the canister used for authorization
func = "checkRequest" # the shared method used for authorization

[cache]
cache_timeout = "1m" # How long responses are cached.

# Timeouts for a connection from the proxy to an upstream.
[upstream_timeouts]
connect_timeout = "20s" # how quickly an upstream answers
read_timeout = "30s" # single socket read operation timeout
total_timeout = "60s" # total timeout from request start to request end

# Modify headers in requests to an upstream.
[request_headers]
remove = ["X-Proxy"] # remove these headers 
add = [["Authorization", "Bearer <OPENAI-API-KEY>"]] # add headers
add_per_host = {"api.openai.com": [["Authorization", "Bearer <OPENAI-API-KEY>"]]}
remove_per_host = {"api.openai.com": ["X-Proxy"]}

# Modify headers in responses (e.g. to IC) from our proxy.
[response_headers]
remove = ["Cookie"] # remove these headers
add = [["Cookie", "userId=789"]] # add these headers
add_per_host = {}
remove_per_host = {}
show_hit_miss = false # false by default. Add `X-JoinProxy-Response: [Hit | Miss]` header
add_forwarded_from_header = false # Add `X-Forwarded-From` useless but widespread HTTP header to the response
```

## Testing

**Warning:** It needs an IPv6-enabled computer to test (the Docker container uses IPv6 internally
because HTTPS outcalls support only IPv6).

For a E2E test, run:
```
docker-compose -f test/e2e/docker-compose.yml -p join-proxy-test up --build --abort-on-container-exit
```

## IC Code

For examples of IC code compatible with this proxy, see `motoko/example/` directory.
