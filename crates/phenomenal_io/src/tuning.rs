//! Hot-path size constants. Single source of truth for streaming
//! chunk sizes, TCP socket buffer sizes, and wire-protocol fixed
//! widths. Importers must take from here so a single edit propagates
//! everywhere — no more hunting down scattered `1024 * 1024` literals.
//!
//! # Why centralised
//!
//! Object-store performance is dominated by a handful of buffer
//! sizes. Operators that benchmark a different chunk size, an
//! operator that wants to tune for a high-BDP link, a profiler that
//! needs to vary one knob and re-measure — all of these need exactly
//! one place to change. Scattering `const CHUNK: usize = 1024 * 1024`
//! across five files made every experiment a search-and-replace.
//!
//! # Currently compile-time
//!
//! All values here are `pub const`. To change them, edit this file
//! and rebuild. A future PR can promote the streaming-chunk family
//! to runtime config (TOML field threaded through `AppState`); the
//! call sites that consume them today already read from this module,
//! so the runtime swap is purely a matter of replacing the `const`
//! reads with field accesses.
//!
//! # Decision log
//!
//! - `STREAM_CHUNK_BYTES = 4 MiB`. Bumped from the historical 1 MiB
//!   (which matched MinIO's `blockSizeV2` and rustfs's
//!   `DEFAULT_READ_BUFFER_SIZE`). 4 MiB matches our `TCP_BUFFER_BYTES`
//!   so a single chunk fills one TCP send/recv window without
//!   pipelining waste, and lands cleanly on the 4 MiB pool bucket
//!   (no bucket spillover).
//! - `DRAIN_CHUNK_BYTES = 64 KiB`. Cold-path drain on streaming-PUT
//!   error: small enough to limit FD memory pressure on simultaneous
//!   error paths, large enough to drain a 4 GiB body without
//!   millions of read syscalls.
//! - `TCP_BUFFER_BYTES = 4 MiB`. Set on every accept and connect so
//!   TCP window-scaling negotiates with enough room for ~25 Gbps at
//!   1 ms RTT (BDP ≈ 3 MiB). Set on the socket BEFORE the SYN
//!   handshake — once negotiated it cannot grow without renegotiation.
//! - `FRAME_HEADER_BYTES = 4`. Wire-format constant: every RPC frame
//!   is `[u32 BE length][body bytes]`. The 4 is the on-wire size of
//!   `u32`. NOT a tunable — changing it would break the wire
//!   protocol. Surfaced as a named constant only to eliminate the
//!   bare `4` magic number at construction sites.

/// Per-iteration chunk size for the streaming pump (read from peer
/// socket → write to local disk, and read from local disk → write to
/// peer socket). Used by every `pump_n` / `pump_compio_to_sink` call
/// site. Bound by:
///   * lower edge: per-syscall overhead amortisation (smaller →
///     more io_uring SQEs per byte)
///   * upper edge: peak in-flight memory (`concurrent_streams ×
///     STREAM_CHUNK_BYTES`) and L2 cache thrash above ~2 MiB
///   * sweet spot for our hardware target (NVMe + 25-100 Gbps NIC):
///     1-8 MiB; we pick 4 MiB to fill the TCP window in one chunk.
pub const STREAM_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// Drain chunk size — used on the cold error path where a streaming
/// PUT references a non-existent disk and we must consume the body
/// off the wire to keep the connection's framing aligned. Smaller
/// than `STREAM_CHUNK_BYTES` because we never expect this path to
/// be hot; minimising memory footprint matters more than syscall
/// amortisation here.
pub const DRAIN_CHUNK_BYTES: usize = 64 * 1024;

/// Per-direction TCP socket buffer (SO_RCVBUF / SO_SNDBUF). Set on
/// every accept and connect. Sized for shard fan-out at ~25 Gbps
/// with 1 ms RTT: BDP = 25 Gbps × 1 ms = ~3.1 MiB; 4 MiB gives
/// headroom and matches our streaming-chunk size so one chunk fills
/// one window. Must be set BEFORE the SYN — TCP window-scaling
/// (RFC 1323) is negotiated in the handshake and the scale factor
/// cannot grow afterwards.
pub const TCP_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// Wire-format constant: bytes occupied by the length prefix of a
/// `[u32 BE length][body]` RPC frame. NOT a tunable — changing this
/// breaks the wire protocol and the peer's framing. Surfaced as a
/// named constant only so `4` doesn't appear as a magic number at
/// every frame-construction site.
pub const FRAME_HEADER_BYTES: usize = std::mem::size_of::<u32>();
