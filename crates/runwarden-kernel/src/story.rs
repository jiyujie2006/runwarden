use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

pub const SECURITY_STORY_SCHEMA_VERSION: &str = "1.0.0";

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
