use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::s3::state::AppState;

pub async fn get(State(state): State<AppState>, Path(key): Path<String>) -> Response {
    match state.store().get(&key) {
        Some(b) => (StatusCode::OK, b).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn put(
    State(state): State<AppState>,
    Path(key): Path<String>,
    body: Bytes,
) -> StatusCode {
    state.store().put(key, &body);
    StatusCode::OK
}
