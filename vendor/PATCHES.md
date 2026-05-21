# Vendored dependency forks

These crates are forks of crates.io releases, wired in via `[patch.crates-io]`
in the workspace `Cargo.toml`. Each keeps `Cargo.toml.orig` (the unmodified
upstream manifest) so the delta is auditable.

## cyper (fork of 0.8.3)

**Change:** added `Client::builder().http2_prior_knowledge()`.

**Why:** the inter-node RPC plane is HTTP/2. Over TLS, HTTP/2 is selected via
ALPN. When `rpc_tls` is absent we connect over plaintext `http://`, where there
is no ALPN, so the client would otherwise default to HTTP/1.1. `http2_prior_knowledge`
makes cyper send the HTTP/2 connection preface immediately (h2c). Paired with the
server serving h2c. Consumed by `PeerClient::new` in
`crates/phenomenal_io/src/remote_fs.rs` (the `None` arm).

**Touched:** `vendor/cyper/src/client.rs` (`pub fn http2_prior_knowledge`).

## h2 (fork of 0.4.14)

**Change:** in `src/proto/mod.rs`,
`DEFAULT_REMOTE_RESET_STREAM_MAX` 20 -> 16384 and
`DEFAULT_LOCAL_RESET_COUNT_MAX` 1024 -> 16384.

**Why:** under high inter-node concurrency a late END_STREAM frame arriving after
we drop the body produced STREAM_CLOSED RST frames that tripped h2's rapid-reset
defenses and tore down the connection. Raising the reset accounting thresholds
absorbs the transient.

**Note:** both values are also reachable through h2's public `Builder` setters
(`max_pending_accept_reset_streams`, `max_local_error_reset_streams`), so this
fork can later be eliminated by setting them on the h2 builder (plumbed through
the cyper fork) instead of editing the defaults.

**Touched:** `vendor/h2/src/proto/mod.rs`.

## Reconciliation

To upgrade either crate: re-fork the new upstream release, re-apply the change
above (diff `Cargo.toml.orig` and the touched file against the fork), bump the
`path` patch. Keeping the fork's version semver-compatible with the graph's
requirement is required for the patch to apply.
