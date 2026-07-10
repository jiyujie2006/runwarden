use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::evidence::hex_sha256;

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
