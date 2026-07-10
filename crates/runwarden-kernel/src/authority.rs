use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Leased,
    Consumed,
    Denied,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalBinding {
    pub session_id: String,
    pub provider: String,
    pub action: String,
    pub argument_hash: String,
    pub authz_id: Option<String>,
    pub actor_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub state: ApprovalState,
    pub binding: ApprovalBinding,
    pub reviewer: Option<String>,
    pub reason: Option<String>,
    #[schemars(with = "Option<String>")]
    pub expires_at: Option<OffsetDateTime>,
}

impl ApprovalRecord {
    pub fn new(approval_id: impl Into<String>, binding: ApprovalBinding) -> Self {
        Self {
            approval_id: approval_id.into(),
            state: ApprovalState::Pending,
            binding,
            reviewer: None,
            reason: None,
            expires_at: None,
        }
    }

    pub fn approve(
        &mut self,
        reviewer: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), ApprovalTransitionError> {
        match self.state {
            ApprovalState::Pending => {
                self.state = ApprovalState::Approved;
                self.reviewer = Some(reviewer.into());
                self.reason = Some(reason.into());
                Ok(())
            }
            _ => Err(ApprovalTransitionError::InvalidState),
        }
    }

    pub fn deny(
        &mut self,
        reviewer: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<(), ApprovalTransitionError> {
        match self.state {
            ApprovalState::Pending => {
                self.state = ApprovalState::Denied;
                self.reviewer = Some(reviewer.into());
                self.reason = Some(reason.into());
                Ok(())
            }
            _ => Err(ApprovalTransitionError::InvalidState),
        }
    }

    pub fn consume_once(
        &mut self,
        binding: &ApprovalBinding,
    ) -> Result<(), ApprovalTransitionError> {
        if &self.binding != binding {
            return Err(ApprovalTransitionError::BindingMismatch);
        }
        match self.state {
            ApprovalState::Approved => {
                self.state = ApprovalState::Consumed;
                Ok(())
            }
            ApprovalState::Consumed => Err(ApprovalTransitionError::AlreadyConsumed),
            _ => Err(ApprovalTransitionError::InvalidState),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalTransitionError {
    #[error("approval is not in a state that allows this transition")]
    InvalidState,
    #[error("approval binding does not match the requested provider call")]
    BindingMismatch,
    #[error("approval was already consumed")]
    AlreadyConsumed,
}
