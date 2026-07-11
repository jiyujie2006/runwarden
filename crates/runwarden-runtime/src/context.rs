use std::path::PathBuf;

use runwarden_kernel::resource::DataClass;
use runwarden_kernel::story::{EvidenceStatus, SecurityStory, StoryProvenance};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::resource_claims::{BudgetDerivationLimits, ResourceExtractionContext};
use runwarden_state::{ActiveDemo, SessionRecord};
use time::OffsetDateTime;

use crate::errors::RuntimeError;
use crate::operation::RuntimeJournal;

const DEFAULT_MAX_FILE_BYTES_PER_CALL: u64 = 4 * 1_024;
const DEFAULT_MAX_NETWORK_RESPONSE_BYTES_PER_CALL: u64 = 4 * 1_024;

pub struct RuntimeStartup {
    pub state_dir: PathBuf,
    pub instance_token: String,
}

impl RuntimeStartup {
    pub fn from_env() -> Result<Self, RuntimeError> {
        Ok(Self {
            state_dir: std::env::var_os("RUNWARDEN_STATE_DIR")
                .map(PathBuf::from)
                .ok_or_else(|| {
                    RuntimeError::ContextUnavailable("RUNWARDEN_STATE_DIR is not set".to_owned())
                })?,
            instance_token: std::env::var("RUNWARDEN_INSTANCE_TOKEN").map_err(|_| {
                RuntimeError::ContextUnavailable("RUNWARDEN_INSTANCE_TOKEN is not set".to_owned())
            })?,
        })
    }
}

/// Immutable, display-safe server authority loaded once at process startup.
/// It retains only the instance-token hash, never the raw inherited token.
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    active: ActiveDemo,
    story: SecurityStory,
    session: SessionRecord,
    extraction: ResourceExtractionContext,
    budget_limits: BudgetDerivationLimits,
}

impl RuntimeContext {
    pub(crate) fn from_server_records(
        active: ActiveDemo,
        story: SecurityStory,
        session: SessionRecord,
        expected_instance_token_hash: &str,
        now: OffsetDateTime,
    ) -> Result<Self, RuntimeError> {
        if active.instance_token_hash != expected_instance_token_hash
            || active.story_id != story.story_id
            || active.session_id != session.session_id
            || session.story_id != story.story_id
            || story.authority.session_id != session.session_id
            || story.authority != session.authority
            || session.policy_snapshot_hash != story.authority.policy_snapshot_hash
            || session.expires_at != story.authority.expires_at
            || session.authority.authz_state != "active"
            || story.provenance != StoryProvenance::Native
            || story.evidence_status != EvidenceStatus::Pending
            || active.heartbeat_at > now
            || now >= session.expires_at
        {
            return Err(RuntimeError::ContextUnavailable(
                "active story, session, authority, token, or lifetime is inconsistent".to_owned(),
            ));
        }
        Sha256Digest::try_from(session.policy_snapshot_hash.clone()).map_err(|_| {
            RuntimeError::ContextUnavailable(
                "active policy snapshot hash is not canonical".to_owned(),
            )
        })?;
        Ok(Self {
            active,
            story,
            session,
            extraction: ResourceExtractionContext {
                filesystem_root: "contest-workspace".to_owned(),
                memory_namespace: "session-memory".to_owned(),
                knowledge_namespace: "curated-knowledge".to_owned(),
                default_classification: DataClass::Internal,
            },
            budget_limits: BudgetDerivationLimits {
                max_file_bytes_per_call: DEFAULT_MAX_FILE_BYTES_PER_CALL,
                max_network_response_bytes_per_call: DEFAULT_MAX_NETWORK_RESPONSE_BYTES_PER_CALL,
            },
        })
    }

    pub fn active_instance(&self) -> &ActiveDemo {
        &self.active
    }

    pub fn story(&self) -> &SecurityStory {
        &self.story
    }

    pub fn session(&self) -> &SessionRecord {
        &self.session
    }

    pub fn extraction_context(&self) -> &ResourceExtractionContext {
        &self.extraction
    }

    pub fn budget_limits(&self) -> &BudgetDerivationLimits {
        &self.budget_limits
    }
}

pub struct RuntimeContextLoader;

impl RuntimeContextLoader {
    pub fn load<J: RuntimeJournal>(
        journal: &J,
        instance_token: &str,
        now: OffsetDateTime,
    ) -> Result<RuntimeContext, RuntimeError> {
        if instance_token.is_empty() || instance_token.len() > 4_096 {
            return Err(RuntimeError::ContextUnavailable(
                "trusted instance token is empty or oversized".to_owned(),
            ));
        }
        let instance_token_hash = Sha256Digest::from_bytes(instance_token.as_bytes());
        let context = journal
            .active_context(instance_token_hash.as_str(), now)
            .map_err(|error| RuntimeError::ContextUnavailable(error.to_string()))?;
        if context.active.instance_token_hash != instance_token_hash.as_str() {
            return Err(RuntimeError::ContextUnavailable(
                "journal returned a foreign active instance".to_owned(),
            ));
        }
        Ok(context)
    }
}
