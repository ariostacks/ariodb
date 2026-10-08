//! Approvals: rules can require a person or a model to allow a statement
//! before it runs. Filled in by the approvals step.

use crate::classify::Statement;
use crate::gate::{ApprovalNeed, Ctx, Refusal, State};

pub async fn require(
    _state: &State,
    _ctx: &Ctx<'_>,
    _statements: &[Statement],
    need: &ApprovalNeed,
) -> Result<(), Refusal> {
    Err(Refusal::by_rule(
        &need.rule,
        format!(
            "{} needs approval from {}, and approvals are not set up",
            need.reason,
            need.approvers.join(", ")
        ),
    ))
}
