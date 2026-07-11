use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::contracts::PolicyDecision;
use crate::evidence::hex_sha256;
use crate::operation::{OperationState, SecurityOperation, SideEffectState};
use crate::session::AuthoritySnapshot;
use crate::trace::{StoryEvent, StoryEventKind, canonical_json_v1};

pub const SECURITY_STORY_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct SchemaVersion(String);

impl SchemaVersion {
    pub fn current() -> Self {
        Self(SECURITY_STORY_SCHEMA_VERSION.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SchemaVersion {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        fn is_canonical_number(component: &str) -> bool {
            !component.is_empty()
                && component.bytes().all(|byte| byte.is_ascii_digit())
                && (component == "0" || !component.starts_with('0'))
                && component.parse::<u64>().is_ok()
        }

        let mut components = value.split('.');
        let (Some(major), Some(minor), Some(patch), None) = (
            components.next(),
            components.next(),
            components.next(),
            components.next(),
        ) else {
            return Err("schema version must contain three numeric components".to_string());
        };
        if !is_canonical_number(major) || !is_canonical_number(minor) || !is_canonical_number(patch)
        {
            return Err(
                "schema version components must be canonical unsigned integers".to_string(),
            );
        }
        if major != "1" {
            return Err("schema version major must be 1".to_string());
        }
        Ok(Self(value))
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

macro_rules! typed_uuid {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
        #[schemars(with = "String")]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl TryFrom<Uuid> for $name {
            type Error = String;

            fn try_from(value: Uuid) -> Result<Self, Self::Error> {
                if value.get_version_num() != 7 || value.get_variant() != uuid::Variant::RFC4122 {
                    return Err(concat!(stringify!($name), " must be UUIDv7").to_string());
                }
                Ok(Self(value))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                let uuid = Uuid::parse_str(&raw).map_err(serde::de::Error::custom)?;
                Self::try_from(uuid).map_err(serde::de::Error::custom)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

typed_uuid!(StoryId);
typed_uuid!(SessionId);
typed_uuid!(OperationId);
typed_uuid!(EventId);
typed_uuid!(ApprovalId);
typed_uuid!(ExecutionLeaseId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct ObservationId(Uuid);

// The frozen story contract exposes explicit construction for observation IDs.
#[allow(clippy::new_without_default)]
impl ObservationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl TryFrom<&str> for ObservationId {
    type Error = String;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let uuid = raw
            .strip_prefix("obs_")
            .ok_or_else(|| "observation id must start with obs_".to_string())
            .and_then(|value| Uuid::parse_str(value).map_err(|error| error.to_string()))?;
        if uuid.get_version_num() != 7 || uuid.get_variant() != uuid::Variant::RFC4122 {
            return Err("observation id must contain UUIDv7".to_string());
        }
        Ok(Self(uuid))
    }
}

impl Serialize for ObservationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("obs_{}", self.0))
    }
}

impl<'de> Deserialize<'de> for ObservationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::try_from(raw.as_str()).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for ObservationId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "obs_{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct InvocationKey(String);

impl InvocationKey {
    pub fn from_hmac_bytes(bytes: [u8; 32]) -> Self {
        Self(format!(
            "inv_{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse(raw: String) -> Result<Self, String> {
        let hexadecimal = raw
            .strip_prefix("inv_")
            .ok_or_else(|| "invocation key must start with inv_".to_string())?;
        if hexadecimal.len() != 64
            || !hexadecimal
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(
                "invocation key must contain exactly 64 lowercase hexadecimal characters"
                    .to_string(),
            );
        }
        Ok(Self(raw))
    }
}

impl Serialize for InvocationKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for InvocationKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Live,
    Deterministic,
    Recorded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    MonitorOnly,
    Enforced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Pending,
    Verified,
    Incomplete,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryStatus {
    Running,
    AwaitingApproval,
    BlockedBeforeSideEffect,
    CompletedWithControlledSideEffect,
    Failed,
    OutcomeUnknown,
    EvidenceInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryProvenance {
    Native,
    LegacyDerived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryStage {
    Identity,
    Attack,
    Model,
    ProposedTool,
    Policy,
    Approval,
    Execution,
    Evidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryStageStatus {
    pub stage: StoryStage,
    pub status: StageStatus,
    pub summary: String,
    pub observation_refs: Vec<ObservationId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Pending,
    Active,
    Completed,
    Blocked,
    Failed,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryIdentity {
    pub agent_id: String,
    pub model_id: String,
    pub actor_id: String,
    pub reviewer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryClaim {
    pub claim_id: String,
    pub text: String,
    pub observation_refs: Vec<ObservationId>,
    pub support_expectation: ReportClaimSupport,
}

#[derive(Debug, Clone, PartialEq, Eq, JsonSchema)]
pub struct ReportClaimSupport {
    pub provider: Option<String>,
    pub event_kind: Option<StoryEventKind>,
    pub policy_decision: Option<PolicyDecision>,
    pub operation_state: Option<OperationState>,
    pub side_effect_state: Option<SideEffectState>,
    pub simulated: Option<bool>,
}

impl ReportClaimSupport {
    fn has_expectation(&self) -> bool {
        self.provider.is_some()
            || self.event_kind.is_some()
            || self.policy_decision.is_some()
            || self.operation_state.is_some()
            || self.side_effect_state.is_some()
            || self.simulated.is_some()
    }
}

impl Serialize for ReportClaimSupport {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !self.has_expectation() {
            return Err(<S::Error as serde::ser::Error>::custom(
                "report claim support must contain at least one expectation",
            ));
        }

        #[derive(Serialize)]
        struct Support<'a> {
            provider: &'a Option<String>,
            event_kind: &'a Option<StoryEventKind>,
            policy_decision: &'a Option<PolicyDecision>,
            operation_state: &'a Option<OperationState>,
            side_effect_state: &'a Option<SideEffectState>,
            simulated: &'a Option<bool>,
        }

        Support {
            provider: &self.provider,
            event_kind: &self.event_kind,
            policy_decision: &self.policy_decision,
            operation_state: &self.operation_state,
            side_effect_state: &self.side_effect_state,
            simulated: &self.simulated,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReportClaimSupport {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Support {
            provider: Option<String>,
            event_kind: Option<StoryEventKind>,
            policy_decision: Option<PolicyDecision>,
            operation_state: Option<OperationState>,
            side_effect_state: Option<SideEffectState>,
            simulated: Option<bool>,
        }

        let support = Support::deserialize(deserializer)?;
        let support = Self {
            provider: support.provider,
            event_kind: support.event_kind,
            policy_decision: support.policy_decision,
            operation_state: support.operation_state,
            side_effect_state: support.side_effect_state,
            simulated: support.simulated,
        };
        if !support.has_expectation() {
            return Err(serde::de::Error::custom(
                "report claim support must contain at least one expectation",
            ));
        }
        Ok(support)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SecurityStory {
    pub schema_version: SchemaVersion,
    pub story_id: StoryId,
    pub title: String,
    pub scenario_id: String,
    pub attack_category: String,
    pub run_mode: RunMode,
    pub enforcement_mode: EnforcementMode,
    pub provenance: StoryProvenance,
    pub status: StoryStatus,
    pub evidence_status: EvidenceStatus,
    pub identity: StoryIdentity,
    pub authority: AuthoritySnapshot,
    pub safe_attack_preview: String,
    pub attack_content_hash: String,
    pub stage_statuses: Vec<StoryStageStatus>,
    pub operations: Vec<SecurityOperation>,
    pub event_count: u64,
    pub report_claims: Vec<StoryClaim>,
    pub final_outcome_summary: String,
    pub final_event_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryReplayFrame {
    pub sequence: u64,
    pub story_version: u64,
    pub event_hash: String,
    pub snapshot_hash: String,
    pub previous_frame_hash: Option<String>,
    pub frame_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    #[schemars(with = "String")]
    pub recorded_at: OffsetDateTime,
    pub story: SecurityStory,
}

impl StoryReplayFrame {
    pub fn seal(
        sequence: u64,
        story_version: u64,
        event_hash: String,
        previous_frame_hash: Option<String>,
        recorded_at: OffsetDateTime,
        story: SecurityStory,
    ) -> Result<Self, serde_json::Error> {
        let snapshot_hash = format!(
            "sha256:{}",
            hex_sha256(&canonical_json_v1(&serde_json::to_value(&story)?)),
        );
        let mut frame = Self {
            sequence,
            story_version,
            event_hash,
            snapshot_hash,
            previous_frame_hash,
            frame_hash: String::new(),
            recorded_at,
            story,
        };
        frame.frame_hash = frame.expected_hash()?;
        Ok(frame)
    }

    pub fn verify(&self) -> Result<(), String> {
        let snapshot = serde_json::to_value(&self.story).map_err(|error| error.to_string())?;
        let actual_snapshot = format!("sha256:{}", hex_sha256(&canonical_json_v1(&snapshot)));
        if actual_snapshot != self.snapshot_hash {
            return Err("replay snapshot hash mismatch".to_string());
        }
        if self.expected_hash().map_err(|error| error.to_string())? != self.frame_hash {
            return Err("replay frame hash mismatch".to_string());
        }
        Ok(())
    }

    fn expected_hash(&self) -> Result<String, serde_json::Error> {
        #[derive(Serialize)]
        struct FrameMaterial<'a> {
            sequence: u64,
            story_version: u64,
            event_hash: &'a str,
            snapshot_hash: &'a str,
            previous_frame_hash: Option<&'a str>,
            #[serde(with = "time::serde::rfc3339")]
            recorded_at: OffsetDateTime,
        }

        let material = FrameMaterial {
            sequence: self.sequence,
            story_version: self.story_version,
            event_hash: &self.event_hash,
            snapshot_hash: &self.snapshot_hash,
            previous_frame_hash: self.previous_frame_hash.as_deref(),
            recorded_at: self.recorded_at,
        };
        Ok(format!(
            "sha256:{}",
            hex_sha256(&canonical_json_v1(&serde_json::to_value(material)?)),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryEvidenceView {
    pub story: SecurityStory,
    pub events: Vec<StoryEvent>,
    pub replay_frames: Vec<StoryReplayFrame>,
}

impl StoryEvidenceView {
    pub fn verify_structure(&self) -> Result<(), String> {
        if self.events.len() != self.replay_frames.len() {
            return Err("story evidence must contain one replay frame per event".to_string());
        }
        if self.story.event_count != self.events.len() as u64 {
            return Err("story event count does not match exported events".to_string());
        }

        let mut previous_event_hash: Option<&str> = None;
        let mut previous_frame_hash: Option<&str> = None;
        for (index, (event, frame)) in self
            .events
            .iter()
            .zip(self.replay_frames.iter())
            .enumerate()
        {
            let expected_sequence = index as u64 + 1;
            if event.sequence != expected_sequence || frame.sequence != expected_sequence {
                return Err("story event and replay frame sequences must be contiguous".to_string());
            }
            if frame.story.event_count != frame.sequence {
                return Err("replay frame story event count must match frame sequence".to_string());
            }
            if event.story_id != self.story.story_id
                || event.session_id != self.story.authority.session_id
                || frame.story.story_id != self.story.story_id
                || frame.story.authority.session_id != self.story.authority.session_id
            {
                return Err("story evidence contains mismatched story or session ids".to_string());
            }
            event.verify()?;
            if event.previous_hash.as_ref().map(|hash| hash.as_str()) != previous_event_hash {
                return Err("story event chain is not contiguous".to_string());
            }
            frame.verify()?;
            if frame.event_hash != event.event_hash() {
                return Err("replay frame event hash does not match sealed event".to_string());
            }
            if frame.previous_frame_hash.as_deref() != previous_frame_hash {
                return Err("replay frame chain is not contiguous".to_string());
            }

            previous_event_hash = Some(event.event_hash());
            previous_frame_hash = Some(frame.frame_hash.as_str());
        }

        if self.story.final_event_hash.as_deref() != previous_event_hash {
            return Err("story final event hash does not match event chain tail".to_string());
        }
        if let Some(final_frame) = self.replay_frames.last()
            && final_frame.story != self.story
        {
            return Err("final replay frame story does not match exported story".to_string());
        }
        Ok(())
    }
}
