use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use time::OffsetDateTime;

use crate::authority::ApprovalState;
use crate::contracts::PolicyDecision;
use crate::evidence::hex_sha256;
use crate::operation::SideEffectState;
use crate::story::{
    ApprovalId, EventId, EvidenceStatus, ObservationId, OperationId, SessionId, StoryId,
};

pub fn canonical_json_v1(value: &Value) -> Vec<u8> {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let sorted = map
                    .iter()
                    .map(|(key, value)| (key.clone(), sort(value)))
                    .collect::<BTreeMap<_, _>>();
                let mut output = Map::new();
                for (key, value) in sorted {
                    output.insert(key, value);
                }
                Value::Object(output)
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            primitive => primitive.clone(),
        }
    }

    serde_json::to_vec(&sort(value)).expect("canonical JSON value serializes")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StoryEventKind {
    OperationProposed,
    PolicyDecision,
    ApprovalLifecycle,
    ProviderExecution,
    ModelCall,
    ToolProposal,
    CausalLink,
    EvidenceVerification,
    InputConsumed,
    SandboxDecision,
    MonitorObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct EventCode(String);

impl TryFrom<String> for EventCode {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b':' | b'/' | b'@' | b'_' | b'-')
            })
        {
            return Err("event code must contain 1-128 allowed ASCII characters".to_string());
        }
        Ok(Self(value))
    }
}

impl From<EventCode> for String {
    fn from(value: EventCode) -> Self {
        value.0
    }
}

impl EventCode {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, JsonSchema)]
#[schemars(with = "String")]
pub struct Sha256Digest(String);

impl TryFrom<String> for Sha256Digest {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let hex = value
            .strip_prefix("sha256:")
            .ok_or_else(|| "digest must start with sha256:".to_string())?;
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("digest must contain 64 lowercase hexadecimal characters".to_string());
        }
        Ok(Self(value))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl Sha256Digest {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex_sha256(bytes)))
    }

    #[allow(dead_code)]
    pub(crate) fn zero_for_construction() -> Self {
        Self(format!("sha256:{}", "0".repeat(64)))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StoryEventPayload {
    OperationProposed {
        provider: EventCode,
        action: EventCode,
        argument_hash: Sha256Digest,
        resource_claim_hash: Sha256Digest,
    },
    PolicyDecision {
        decision: PolicyDecision,
        reason_code: EventCode,
        policy_snapshot_hash: Sha256Digest,
    },
    ApprovalLifecycle {
        approval_id: ApprovalId,
        state: ApprovalState,
        reviewer_id_hash: Option<Sha256Digest>,
    },
    ProviderExecution {
        execution_status: EventCode,
        side_effect_state: SideEffectState,
        output_hash: Option<Sha256Digest>,
        receipt_hash: Option<Sha256Digest>,
    },
    ModelCall {
        model_call_id: EventCode,
        phase: EventCode,
        model_id: Option<EventCode>,
        content_hash: Sha256Digest,
        filter_state: Option<EventCode>,
        risk_codes: Vec<EventCode>,
        forwarded: Option<bool>,
        content_bytes: u64,
        proposal_count: Option<u64>,
    },
    ToolProposal {
        proposal_id: EventCode,
        upstream_tool_call_id: Option<EventCode>,
        provider: EventCode,
        action: EventCode,
        argument_hash: Sha256Digest,
    },
    CausalLink {
        proposal_id: Option<EventCode>,
        status: EventCode,
        reason_code: Option<EventCode>,
        candidate_count: u64,
    },
    EvidenceVerification {
        status: EvidenceStatus,
        error_codes: Vec<EventCode>,
        claim_count: u64,
        candidate_chain_head: Sha256Digest,
        candidate_story_version: u64,
        verifier_version: EventCode,
        event_chain_verified: bool,
        report_claims_verified: bool,
    },
    InputConsumed {
        asset_id: EventCode,
        content_hash: Sha256Digest,
    },
    SandboxDecision {
        profile_hash: Sha256Digest,
        isolation_state: EventCode,
        reason_code: Option<EventCode>,
    },
    MonitorObservation {
        shadow_decision: PolicyDecision,
        baseline_disposition: EventCode,
        simulated_effect_hash: Option<Sha256Digest>,
    },
}

impl StoryEventPayload {
    pub fn kind(&self) -> StoryEventKind {
        match self {
            Self::OperationProposed { .. } => StoryEventKind::OperationProposed,
            Self::PolicyDecision { .. } => StoryEventKind::PolicyDecision,
            Self::ApprovalLifecycle { .. } => StoryEventKind::ApprovalLifecycle,
            Self::ProviderExecution { .. } => StoryEventKind::ProviderExecution,
            Self::ModelCall { .. } => StoryEventKind::ModelCall,
            Self::ToolProposal { .. } => StoryEventKind::ToolProposal,
            Self::CausalLink { .. } => StoryEventKind::CausalLink,
            Self::EvidenceVerification { .. } => StoryEventKind::EvidenceVerification,
            Self::InputConsumed { .. } => StoryEventKind::InputConsumed,
            Self::SandboxDecision { .. } => StoryEventKind::SandboxDecision,
            Self::MonitorObservation { .. } => StoryEventKind::MonitorObservation,
        }
    }
}

/// A payload whose serialized shape is restricted to [`StoryEventPayload`].
///
/// External code cannot construct the wrapper directly:
///
/// ```compile_fail
/// use runwarden_kernel::trace::{EventCode, RedactedEventPayload, Sha256Digest, StoryEventPayload};
///
/// let typed = StoryEventPayload::InputConsumed {
///     asset_id: EventCode::try_from("asset-1".to_string()).unwrap(),
///     content_hash: Sha256Digest::from_bytes(b"input"),
/// };
/// let redacted = RedactedEventPayload(typed);
/// ```
///
/// Nor can it mutate the validated inner payload:
///
/// ```compile_fail
/// use runwarden_kernel::trace::{RedactedEventPayload, StoryEventPayload};
///
/// let mut redacted: RedactedEventPayload = serde_json::from_str(
///     r#"{"kind":"input_consumed","asset_id":"asset-1","content_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
/// ).unwrap();
/// redacted.0 = StoryEventPayload::InputConsumed {
///     asset_id: "asset-2".to_string().try_into().unwrap(),
///     content_hash: runwarden_kernel::trace::Sha256Digest::from_bytes(b"replacement"),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct RedactedEventPayload(StoryEventPayload);

impl RedactedEventPayload {
    pub(crate) fn from_typed(payload: StoryEventPayload) -> Self {
        Self(payload)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryEvent {
    pub obs_id: ObservationId,
    pub event_id: EventId,
    pub story_id: StoryId,
    pub session_id: SessionId,
    pub sequence: u64,
    pub operation_id: Option<OperationId>,
    pub event_type: StoryEventKind,
    pub provider: Option<EventCode>,
    payload: RedactedEventPayload,
    pub previous_hash: Option<Sha256Digest>,
    event_hash: Sha256Digest,
    #[serde(with = "time::serde::rfc3339")]
    #[schemars(with = "String")]
    pub recorded_at: OffsetDateTime,
}

impl StoryEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        obs_id: ObservationId,
        event_id: EventId,
        story_id: StoryId,
        session_id: SessionId,
        sequence: u64,
        operation_id: Option<OperationId>,
        provider: Option<EventCode>,
        payload: StoryEventPayload,
        previous_hash: Option<Sha256Digest>,
        recorded_at: OffsetDateTime,
    ) -> Self {
        let event_type = payload.kind();
        let mut event = Self {
            obs_id,
            event_id,
            story_id,
            session_id,
            sequence,
            operation_id,
            event_type,
            provider,
            payload: RedactedEventPayload::from_typed(payload),
            previous_hash,
            event_hash: Sha256Digest::zero_for_construction(),
            recorded_at,
        };
        event.event_hash = event.expected_hash();
        event
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.event_type != self.payload.0.kind() {
            Err("event type does not match typed payload kind".to_string())
        } else if self.event_hash == self.expected_hash() {
            Ok(())
        } else {
            Err("event hash does not match canonical event material".to_string())
        }
    }

    pub fn event_hash(&self) -> &str {
        self.event_hash.as_str()
    }

    pub fn payload(&self) -> &StoryEventPayload {
        &self.payload.0
    }

    fn expected_hash(&self) -> Sha256Digest {
        #[derive(Serialize)]
        struct CanonicalEventMaterial<'a> {
            obs_id: &'a ObservationId,
            event_id: &'a EventId,
            story_id: &'a StoryId,
            session_id: &'a SessionId,
            sequence: u64,
            operation_id: Option<&'a OperationId>,
            event_type: StoryEventKind,
            provider: Option<&'a EventCode>,
            payload: &'a RedactedEventPayload,
            previous_hash: Option<&'a Sha256Digest>,
            #[serde(with = "time::serde::rfc3339")]
            recorded_at: OffsetDateTime,
        }

        let material = CanonicalEventMaterial {
            obs_id: &self.obs_id,
            event_id: &self.event_id,
            story_id: &self.story_id,
            session_id: &self.session_id,
            sequence: self.sequence,
            operation_id: self.operation_id.as_ref(),
            event_type: self.event_type,
            provider: self.provider.as_ref(),
            payload: &self.payload,
            previous_hash: self.previous_hash.as_ref(),
            recorded_at: self.recorded_at,
        };
        Sha256Digest::from_bytes(&canonical_json_v1(
            &serde_json::to_value(material).expect("event material serializes"),
        ))
    }
}
