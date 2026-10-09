//! MySQL and MariaDB SQL, understood well enough to judge it.
//!
//! Produces the same `Statement` the Postgres classifier does, with
//! `engine = "mysql"`, so the policy, rules, approvals and audit log work
//! unchanged.

use crate::classify::{ParseError, Statement};

/// Split a query string into statements and classify each one.
pub fn classify(_sql: &str) -> Result<Vec<Statement>, ParseError> {
    Err(ParseError("MySQL support is not built yet".to_string()))
}

/// Make table names relative to the session's database: names in
/// `database` become unqualified (`app.orders` becomes `orders`), names in
/// other databases stay qualified, so `[agents.mysql] tables = ["orders"]`
/// means `orders` in `database` only.
pub fn scope_to_database(_statements: &mut [Statement], _database: &str) {}
