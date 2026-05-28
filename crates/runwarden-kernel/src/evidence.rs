use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TraceEvent {
    pub obs_id: String,
    pub event_type: String,
    pub provider: Option<String>,
    pub payload: Value,
    pub previous_hash: Option<String>,
    pub event_hash: String,
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryTraceStore {
    events: Vec<TraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceQuery {
    pub offset: usize,
    pub limit: usize,
    pub provider: Option<String>,
    pub event_type: Option<String>,
    pub obs_prefix: Option<String>,
    pub max_bytes: Option<usize>,
}

impl Default for TraceQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 100,
            provider: None,
            event_type: None,
            obs_prefix: None,
            max_bytes: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TracePage {
    pub offset: usize,
    pub limit: usize,
    pub total_matching: usize,
    pub next_offset: Option<usize>,
    pub truncated_by_bytes: bool,
    pub events: Vec<TraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TraceExportPage {
    pub verified: bool,
    pub page: TracePage,
    pub compact_refs: Vec<String>,
}

impl InMemoryTraceStore {
    pub fn append(&mut self, event: TraceEvent) {
        self.events.push(event);
    }

    pub fn append_signed(
        &mut self,
        obs_id: impl Into<String>,
        event_type: impl Into<String>,
        provider: Option<impl Into<String>>,
        payload: Value,
    ) -> TraceEvent {
        let previous_hash = self.events.last().map(|event| event.event_hash.clone());
        let event = TraceEvent::sealed(
            obs_id.into(),
            event_type.into(),
            provider.map(Into::into),
            payload,
            previous_hash,
        );
        self.events.push(event.clone());
        event
    }

    pub fn page(&self, offset: usize, limit: usize) -> &[TraceEvent] {
        let start = offset.min(self.events.len());
        let end = (start + limit).min(self.events.len());
        &self.events[start..end]
    }

    pub fn query(&self, query: TraceQuery) -> TracePage {
        let matching: Vec<_> = self
            .events
            .iter()
            .filter(|event| trace_event_matches(event, &query))
            .collect();
        let total_matching = matching.len();
        let mut events = Vec::new();
        let mut bytes_used = 0usize;
        let mut truncated_by_bytes = false;

        for event in matching
            .iter()
            .skip(query.offset)
            .take(query.limit)
            .copied()
        {
            let event_bytes = serde_json::to_vec(event)
                .expect("trace event should serialize")
                .len();
            if let Some(max_bytes) = query.max_bytes
                && bytes_used + event_bytes > max_bytes
            {
                truncated_by_bytes = true;
                break;
            }
            bytes_used += event_bytes;
            events.push(event.clone());
        }

        let consumed = events.len();
        let next_offset = if query.offset + consumed < total_matching {
            Some(query.offset + consumed)
        } else {
            None
        };

        TracePage {
            offset: query.offset,
            limit: query.limit,
            total_matching,
            next_offset,
            truncated_by_bytes,
            events,
        }
    }

    pub fn stream_export(
        &self,
        query: TraceQuery,
    ) -> Result<TraceExportPage, TraceVerificationError> {
        self.verify_hash_chain()?;
        let page = self.query(query);
        let compact_refs = page
            .events
            .iter()
            .map(|event| event.obs_id.clone())
            .collect();
        Ok(TraceExportPage {
            verified: true,
            page,
            compact_refs,
        })
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn verify_hash_chain(&self) -> Result<(), TraceVerificationError> {
        let mut previous_hash = None;
        for (offset, event) in self.events.iter().enumerate() {
            if event.previous_hash != previous_hash {
                return Err(TraceVerificationError {
                    offset,
                    obs_id: event.obs_id.clone(),
                    reason: "previous hash does not match prior event".to_string(),
                });
            }

            let expected_hash = TraceEvent::hash_material(
                &event.obs_id,
                &event.event_type,
                event.provider.as_deref(),
                &event.payload,
                event.previous_hash.as_deref(),
            );
            if event.event_hash != expected_hash {
                return Err(TraceVerificationError {
                    offset,
                    obs_id: event.obs_id.clone(),
                    reason: "event hash does not match event payload".to_string(),
                });
            }
            previous_hash = Some(event.event_hash.clone());
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn events_mut_for_test(&mut self) -> &mut [TraceEvent] {
        &mut self.events
    }
}

fn trace_event_matches(event: &TraceEvent, query: &TraceQuery) -> bool {
    if let Some(provider) = &query.provider
        && event.provider.as_deref() != Some(provider.as_str())
    {
        return false;
    }
    if let Some(event_type) = &query.event_type
        && event.event_type != *event_type
    {
        return false;
    }
    if let Some(obs_prefix) = &query.obs_prefix
        && !event.obs_id.starts_with(obs_prefix)
    {
        return false;
    }
    true
}

impl TraceEvent {
    pub fn sealed(
        obs_id: String,
        event_type: String,
        provider: Option<String>,
        payload: Value,
        previous_hash: Option<String>,
    ) -> Self {
        let event_hash = Self::hash_material(
            &obs_id,
            &event_type,
            provider.as_deref(),
            &payload,
            previous_hash.as_deref(),
        );
        Self {
            obs_id,
            event_type,
            provider,
            payload,
            previous_hash,
            event_hash,
        }
    }

    fn hash_material(
        obs_id: &str,
        event_type: &str,
        provider: Option<&str>,
        payload: &Value,
        previous_hash: Option<&str>,
    ) -> String {
        #[derive(Serialize)]
        struct HashMaterial<'a> {
            previous_hash: Option<&'a str>,
            obs_id: &'a str,
            event_type: &'a str,
            provider: Option<&'a str>,
            payload: &'a Value,
        }

        let material = HashMaterial {
            previous_hash,
            obs_id,
            event_type,
            provider,
            payload,
        };
        let bytes = serde_json::to_vec(&material).expect("trace hash material serializes");
        hex_sha256(&bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("trace hash chain verification failed at offset {offset} ({obs_id}): {reason}")]
pub struct TraceVerificationError {
    pub offset: usize,
    pub obs_id: String,
    pub reason: String,
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut hex, "{byte:02x}").expect("writing to string cannot fail");
    }
    hex
}
