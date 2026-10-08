//! The dashboard's read and management API beyond approvals.

use crate::gate::State;
use axum::Router;
use std::sync::Arc;

pub fn routes() -> Router<Arc<State>> {
    Router::new()
}
