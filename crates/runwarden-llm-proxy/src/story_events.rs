use std::path::Path;

use anyhow::{Context, Result};
use runwarden_kernel::story::{SessionId, StoryId};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_state::{
    FilterDecisionEvent, ModelCallCompletion, ModelCallIntent, ModelJournalBinding,
    ProposedToolCall, StateStore,
};
use time::OffsetDateTime;

use crate::{Cli, MODEL_EGRESS_PROVIDER, canonical_upstream_origin};

pub const STORY_JOURNAL_UNAVAILABLE: &str = "story_journal_unavailable";
pub const MODEL_COMPLETION_COMMIT_FAILED: &str = "model_completion_commit_failed";
const MAX_TRUSTED_TOKEN_BYTES: usize = 4_096;

/// The display-safe story/session identity needed to construct model intents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoryContext {
    pub story_id: StoryId,
    pub session_id: SessionId,
}

/// The proxy's journal boundary. Implementations must commit the complete
/// domain mutation atomically; callers never compensate with a second writer.
pub trait StoryEventSink: Send + Sync {
    fn begin_model_call(
        &self,
        intent: ModelCallIntent,
        input_filter: FilterDecisionEvent,
    ) -> Result<(), String>;

    fn complete_model_call(
        &self,
        input: ModelCallCompletion,
        proposals: Vec<ProposedToolCall>,
    ) -> Result<(), String>;

    fn mark_evidence_invalid(&self, reason: &str) -> Result<(), String>;
}

/// Production sink backed by the authoritative SQLite story journal.
///
/// The raw inherited instance token is hashed during construction and is never
/// retained by this value.
#[derive(Clone)]
pub struct JournalStoryEventSink {
    store: StateStore,
    binding: ModelJournalBinding,
    canonical_origin: String,
}

impl JournalStoryEventSink {
    /// Validate the exact active instance and model-egress authority using a
    /// trusted in-memory token. The token bytes are borrowed only long enough
    /// to hash them.
    pub fn from_trusted_token(cli: &Cli, instance_token: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_trusted_token_at(cli, instance_token.as_ref(), OffsetDateTime::now_utc())
    }

    pub(crate) fn from_trusted_token_at(
        cli: &Cli,
        instance_token: &[u8],
        now: OffsetDateTime,
    ) -> Result<Self> {
        validate_trusted_token(instance_token)?;
        let token_hash = Sha256Digest::from_bytes(instance_token);
        let origin = canonical_upstream_origin(&cli.upstream)?;
        Self::from_token_hash_at(
            &cli.state_dir,
            token_hash.as_str(),
            MODEL_EGRESS_PROVIDER,
            &origin,
            now,
        )
    }

    fn from_token_hash_at(
        state_dir: &Path,
        token_hash: &str,
        upstream_provider: &str,
        canonical_origin: &str,
        now: OffsetDateTime,
    ) -> Result<Self> {
        let store = StateStore::open(state_dir).context("open LLM proxy story journal")?;
        let binding = store
            .bind_model_journal(token_hash, upstream_provider, canonical_origin, now)
            .context("bind LLM proxy to the active story journal")?;
        Ok(Self {
            store,
            binding,
            canonical_origin: canonical_origin.to_owned(),
        })
    }

    pub fn story_context(&self) -> StoryContext {
        StoryContext {
            story_id: self.binding.story_id(),
            session_id: self.binding.session_id(),
        }
    }

    pub(crate) fn validate_prepared_cli(&self, cli: &Cli) -> Result<()> {
        anyhow::ensure!(
            canonical_upstream_origin(&cli.upstream)? == self.canonical_origin,
            "prepared LLM journal origin does not match proxy upstream"
        );
        Ok(())
    }
}

impl StoryEventSink for JournalStoryEventSink {
    fn begin_model_call(
        &self,
        intent: ModelCallIntent,
        input_filter: FilterDecisionEvent,
    ) -> Result<(), String> {
        self.store
            .begin_model_call(&self.binding, intent, input_filter)
            .map_err(|_| STORY_JOURNAL_UNAVAILABLE.to_owned())
    }

    fn complete_model_call(
        &self,
        input: ModelCallCompletion,
        proposals: Vec<ProposedToolCall>,
    ) -> Result<(), String> {
        let retry_input = input.clone();
        let retry_proposals = proposals.clone();
        match self
            .store
            .complete_model_call(&self.binding, input, proposals)
        {
            Ok(()) => Ok(()),
            Err(_) => self
                .store
                .complete_model_call(&self.binding, retry_input, retry_proposals)
                .map_err(|_| STORY_JOURNAL_UNAVAILABLE.to_owned()),
        }
    }

    fn mark_evidence_invalid(&self, reason: &str) -> Result<(), String> {
        self.store
            .mark_model_evidence_invalid(&self.binding, reason, OffsetDateTime::now_utc())
            .map_err(|_| STORY_JOURNAL_UNAVAILABLE.to_owned())
    }
}

fn validate_trusted_token(token: &[u8]) -> Result<()> {
    anyhow::ensure!(
        !token.is_empty() && token.len() <= MAX_TRUSTED_TOKEN_BYTES,
        "trusted instance token is empty or oversized"
    );
    Ok(())
}
