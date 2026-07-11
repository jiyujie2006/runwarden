use std::time::{Duration as StdDuration, Instant};

use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::story::OperationId;
use runwarden_state::ExpireApprovalInput;

use crate::errors::RuntimeError;
use crate::operation::{Clock, RuntimeJournal};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalWaitPolicy {
    pub timeout: StdDuration,
    pub poll_interval: StdDuration,
}

impl ApprovalWaitPolicy {
    pub fn contest_default() -> Self {
        Self {
            timeout: StdDuration::from_secs(120),
            poll_interval: StdDuration::from_millis(100),
        }
    }

    pub fn immediate() -> Self {
        Self {
            timeout: StdDuration::ZERO,
            poll_interval: StdDuration::from_millis(1),
        }
    }
}

impl Default for ApprovalWaitPolicy {
    fn default() -> Self {
        Self::contest_default()
    }
}

pub(crate) enum ApprovalWaitOutcome {
    Approved,
    Terminal,
    TimedOut,
}

pub(crate) fn wait_for_approval<J, C>(
    journal: &J,
    clock: &C,
    operation_id: OperationId,
    policy: ApprovalWaitPolicy,
) -> Result<ApprovalWaitOutcome, RuntimeError>
where
    J: RuntimeJournal,
    C: Clock,
{
    if policy.timeout.is_zero() {
        return Ok(ApprovalWaitOutcome::TimedOut);
    }
    let deadline = Instant::now()
        .checked_add(policy.timeout)
        .ok_or_else(|| RuntimeError::ContextUnavailable("approval wait overflowed".to_owned()))?;

    loop {
        if Instant::now() >= deadline {
            return Ok(ApprovalWaitOutcome::TimedOut);
        }
        let approval = journal
            .approval_for_operation(operation_id)
            .map_err(|_| before_execution("approval_for_operation"))?
            .ok_or_else(|| before_execution("approval_for_operation"))?;
        // A database read can block behind a writer. Never advance an
        // approval observed only after the configured wall-time deadline.
        if Instant::now() >= deadline {
            return Ok(ApprovalWaitOutcome::TimedOut);
        }
        match approval.state {
            ApprovalState::Approved => return Ok(ApprovalWaitOutcome::Approved),
            ApprovalState::Denied | ApprovalState::Expired | ApprovalState::Revoked => {
                return Ok(ApprovalWaitOutcome::Terminal);
            }
            ApprovalState::Leased | ApprovalState::Consumed => {
                return Ok(ApprovalWaitOutcome::Terminal);
            }
            ApprovalState::Pending => {
                let now = clock.now();
                if now >= approval.expires_at {
                    let operation = journal
                        .operation(operation_id)
                        .map_err(|_| before_execution("expire_approval"))?;
                    match journal.expire_approval(ExpireApprovalInput {
                        approval_id: approval.approval_id,
                        expected_approval_version: approval.version,
                        expected_operation_version: operation.version,
                        now,
                    }) {
                        Ok(_) => return Ok(ApprovalWaitOutcome::Terminal),
                        Err(_) => {
                            // A reviewer may have won the CAS at the expiry
                            // boundary. Re-read instead of guessing the state,
                            // but do not spin forever on a durable write fault.
                            let current = journal
                                .approval_for_operation(operation_id)
                                .map_err(|_| before_execution("expire_approval"))?
                                .ok_or_else(|| before_execution("expire_approval"))?;
                            if current.state == ApprovalState::Pending
                                && current.version == approval.version
                            {
                                return Err(before_execution("expire_approval"));
                            }
                            continue;
                        }
                    }
                }
            }
        }

        let wall_now = Instant::now();
        if wall_now >= deadline {
            return Ok(ApprovalWaitOutcome::TimedOut);
        }
        let remaining = deadline.saturating_duration_since(wall_now);
        std::thread::sleep(policy.poll_interval.min(remaining));
    }
}

fn before_execution(point: &'static str) -> RuntimeError {
    RuntimeError::JournalBeforeExecution(point.to_owned())
}
