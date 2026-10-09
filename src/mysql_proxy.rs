//! The MySQL front door: agents connect with any MySQL client and their
//! token; ariodb judges each statement and relays it to the real server as
//! its own login.

use crate::gate::State;
use std::sync::Arc;

/// Accept agents on `[mysql] listen`. Returns only on error; pending forever
/// when the listener is off.
pub async fn serve(state: Arc<State>) -> Result<(), String> {
    if state.config().mysql.listen.is_empty() {
        return std::future::pending().await;
    }
    Err("the MySQL proxy is not built yet".to_string())
}
