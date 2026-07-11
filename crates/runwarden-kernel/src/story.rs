use schemars::{
    JsonSchema,
    r#gen::SchemaGenerator,
    schema::{
        InstanceType, ObjectValidation, Schema, SchemaObject, StringValidation, SubschemaValidation,
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::contracts::PolicyDecision;
use crate::evidence::hex_sha256;
use crate::operation::{OperationState, SecurityOperation, SideEffectState};
use crate::session::AuthoritySnapshot;
use crate::trace::{StoryEvent, StoryEventKind, canonical_json_v1};

pub const SECURITY_STORY_SCHEMA_VERSION: &str = "1.0.0";

const U64_DECIMAL_SCHEMA_COMPONENT: &str = concat!(
    "(?:0|[1-9][0-9]{0,18}",
    "|1[0-7][0-9]{18}",
    "|18[0-3][0-9]{17}",
    "|184[0-3][0-9]{16}",
    "|1844[0-5][0-9]{15}",
    "|18446[0-6][0-9]{14}",
    "|184467[0-3][0-9]{13}",
    "|1844674[0-3][0-9]{12}",
    "|184467440[0-6][0-9]{10}",
    "|1844674407[0-2][0-9]{9}",
    "|18446744073[0-6][0-9]{8}",
    "|1844674407370[0-8][0-9]{6}",
    "|18446744073709[0-4][0-9]{5}",
    "|184467440737095[0-4][0-9]{4}",
    "|18446744073709550[0-9]{3}",
    "|18446744073709551[0-5][0-9]{2}",
    "|1844674407370955160[0-9]",
    "|1844674407370955161[0-5])",
);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion(String);

impl JsonSchema for SchemaVersion {
    fn schema_name() -> String {
        "SchemaVersion".to_string()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                min_length: Some(5),
                max_length: Some(43),
                pattern: Some(format!(
                    r"^1\.{U64_DECIMAL_SCHEMA_COMPONENT}\.{U64_DECIMAL_SCHEMA_COMPONENT}$"
                )),
            })),
            ..Default::default()
        })
    }
}

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
        pub struct $name(
            #[schemars(
                length(equal = 36),
                regex(pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            )]
            Uuid,
        );

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
                if raw != uuid.to_string() {
                    return Err(serde::de::Error::custom(concat!(
                        stringify!($name),
                        " must use canonical lowercase hyphenated UUID text"
                    )));
                }
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
pub struct ObservationId(
    #[schemars(
        with = "String",
        length(equal = 40),
        regex(
            pattern = r"^obs_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
    )]
    Uuid,
);

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
        let uuid_text = raw
            .strip_prefix("obs_")
            .ok_or_else(|| "observation id must start with obs_".to_string())?;
        let uuid = Uuid::parse_str(uuid_text).map_err(|error| error.to_string())?;
        if uuid_text != uuid.to_string() {
            return Err(
                "observation id must use canonical lowercase hyphenated UUID text".to_string(),
            );
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportClaimSupport {
    pub provider: Option<String>,
    pub event_kind: Option<StoryEventKind>,
    pub policy_decision: Option<PolicyDecision>,
    pub operation_state: Option<OperationState>,
    pub side_effect_state: Option<SideEffectState>,
    pub simulated: Option<bool>,
}

impl JsonSchema for ReportClaimSupport {
    fn schema_name() -> String {
        "ReportClaimSupport".to_string()
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut object = ObjectValidation::default();
        object.properties.insert(
            "provider".to_string(),
            generator.subschema_for::<Option<String>>(),
        );
        object.properties.insert(
            "event_kind".to_string(),
            generator.subschema_for::<Option<StoryEventKind>>(),
        );
        object.properties.insert(
            "policy_decision".to_string(),
            generator.subschema_for::<Option<PolicyDecision>>(),
        );
        object.properties.insert(
            "operation_state".to_string(),
            generator.subschema_for::<Option<OperationState>>(),
        );
        object.properties.insert(
            "side_effect_state".to_string(),
            generator.subschema_for::<Option<SideEffectState>>(),
        );
        object.properties.insert(
            "simulated".to_string(),
            generator.subschema_for::<Option<bool>>(),
        );
        object.additional_properties = Some(Box::new(Schema::Bool(false)));

        let any_of = vec![
            required_claim_support_property::<String>(generator, "provider"),
            required_claim_support_property::<StoryEventKind>(generator, "event_kind"),
            required_claim_support_property::<PolicyDecision>(generator, "policy_decision"),
            required_claim_support_property::<OperationState>(generator, "operation_state"),
            required_claim_support_property::<SideEffectState>(generator, "side_effect_state"),
            required_claim_support_property::<bool>(generator, "simulated"),
        ];

        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::Object.into()),
            subschemas: Some(Box::new(SubschemaValidation {
                any_of: Some(any_of),
                ..Default::default()
            })),
            object: Some(Box::new(object)),
            ..Default::default()
        })
    }
}

fn required_claim_support_property<T: JsonSchema>(
    generator: &mut SchemaGenerator,
    field: &str,
) -> Schema {
    let mut object = ObjectValidation::default();
    object.required.insert(field.to_string());
    object
        .properties
        .insert(field.to_string(), generator.subschema_for::<T>());
    Schema::Object(SchemaObject {
        instance_type: Some(InstanceType::Object.into()),
        object: Some(Box::new(object)),
        ..Default::default()
    })
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
            if frame.story.final_event_hash.as_deref() != Some(frame.event_hash.as_str()) {
                return Err(
                    "replay frame story final event hash must match frame event hash".to_string(),
                );
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
