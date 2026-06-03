//! S3 HTTP frontend.
//!
//! Submodules:
//!
//!   * `app`        — `Router` builder + per-runtime `cyper_axum::serve`
//!                    helper.
//!   * `state`      — `AppState` (shared engine + auth handle) accepted
//!                    by every handler via `axum::extract::State`.
//!   * `error`      — `AppError` + `IntoResponse` mapping to S3 XML
//!                    error envelopes with the right HTTP status.
//!   * `xml`        — typed XML response shapes (LocationConstraint,
//!                    ListBucketResult, …).
//!   * `middleware/sigv4` — `tower::Layer` running SigV4 verification
//!                    before any handler executes.
//!   * `handlers/buckets` — bucket-scoped operations (list, create,
//!                    delete, head, location, versioning, list-objects-v2).
//!   * `handlers/objects` — object-scoped operations (get, head, delete,
//!                    put).
//!
//! Threading: each pinned-core compio runtime calls
//! `cyper_axum::serve(listener, app)` once with its own `SO_REUSEPORT`
//! listener. cyper-axum's `CompioExecutor` polls every Service future
//! on the runtime's own thread, so `AppState`'s manual `Send + Sync`
//! impls are sound by single-thread confinement.

pub mod app;
pub mod body_source;
pub mod error;
pub mod handlers;
pub mod listener;
pub mod middleware;
pub mod state;
pub mod xml;
