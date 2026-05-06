//! Per-runtime application state shared across axum handlers.
//!
//! Holds `Rc<Engine>` and `Rc<AuthState>`. Both are `!Send`, but axum's
//! `State<S>` requires `S: Clone + Send + Sync + 'static`, so we
//! manually claim `Send + Sync` for `AppState`.
//!
//! # Safety
//!
//! The `unsafe impl Send` / `unsafe impl Sync` are sound because:
//!
//!   1. Each compio runtime runs on a single `sched_setaffinity`-pinned
//!      OS thread (see `main::run_runtime`).
//!   2. `cyper_axum::serve(listener, app)` is invoked once per runtime
//!      with its own `SO_REUSEPORT` listener and spawns every per-
//!      connection task into the *current* compio runtime via
//!      `CompioExecutor::execute → compio::runtime::spawn`.
//!   3. compio's runtime is single-threaded; `compio::runtime::spawn`
//!      always polls the future on the same OS thread.
//!   4. Therefore the `Rc`s inside `AppState` are never accessed from a
//!      thread other than the one that created them.
//!
//! The `Send`/`Sync` impl is a *type-level* lie that holds at runtime
//! under the invariants above.

use std::rc::Rc;

use phenomenal_storage::Engine;

use crate::auth::AuthState;

/// Shared state passed to every axum handler via `State<AppState>`.
/// Cloning is cheap (one refcount bump).
#[derive(Clone)]
pub struct AppState {
    inner: Rc<AppStateInner>,
}

struct AppStateInner {
    engine: Rc<Engine>,
    auth:   Rc<AuthState>,
}

// SAFETY: see module-level docs — single-thread confinement.
unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

impl AppState {
    pub fn new(engine: Rc<Engine>, auth: Rc<AuthState>) -> Self {
        Self {
            inner: Rc::new(AppStateInner { engine, auth }),
        }
    }

    pub fn engine(&self) -> &Rc<Engine> { &self.inner.engine }
    pub fn auth(&self)   -> &Rc<AuthState> { &self.inner.auth }
}
