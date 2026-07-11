use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::artifact::WorkspaceRelativePath;
use crate::story::{EvidenceStatus, RunMode, SchemaVersion, StoryId};
use crate::trace::{Sha256Digest, canonical_json_v1};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleFileDigest {
    relative_path: WorkspaceRelativePath,
    pub bytes: u64,
    pub sha256: Sha256Digest,
}

impl BundleFileDigest {
    pub fn new(
        relative_path: impl Into<String>,
        bytes: u64,
        sha256: impl Into<String>,
    ) -> Result<Self, String> {
        let relative_path = WorkspaceRelativePath::try_from(relative_path.into())
            .map_err(|error| error.to_string())?;
        Ok(Self {
            relative_path,
            bytes,
            sha256: Sha256Digest::try_from(sha256.into())?,
        })
    }

    pub fn relative_path(&self) -> &WorkspaceRelativePath {
        &self.relative_path
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleVerificationSummary {
    pub event_chain_verified: bool,
    pub report_claims_verified: bool,
    pub scenario_assertions_verified: Option<bool>,
    pub evidence_status: EvidenceStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StoryBundleManifest {
    pub schema_version: SchemaVersion,
    pub bundle_id: String,
    pub story_id: StoryId,
    pub story_version: u64,
    pub run_mode: RunMode,
    pub scenario_id: String,
    pub created_at: String,
    pub git_sha: String,
    pub source_dirty: bool,
    pub chain_head: Sha256Digest,
    pub final_frame_hash: Sha256Digest,
    pub signature_algorithm: String,
    pub key_id: String,
    pub files: Vec<BundleFileDigest>,
    pub verification: BundleVerificationSummary,
}

impl StoryBundleManifest {
    pub fn signature_material(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut normalized = self.clone();
        normalized.files.sort_by(|left, right| {
            left.relative_path
                .as_str()
                .cmp(right.relative_path.as_str())
        });
        let value = serde_json::to_value(normalized)?;
        Ok(canonical_json_v1(&value))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn file(relative_path: &str, contents: &[u8]) -> BundleFileDigest {
        BundleFileDigest::new(
            relative_path,
            contents.len() as u64,
            Sha256Digest::from_bytes(contents).as_str(),
        )
        .unwrap()
    }

    fn manifest(files: Vec<BundleFileDigest>) -> StoryBundleManifest {
        StoryBundleManifest {
            schema_version: SchemaVersion::current(),
            bundle_id: "bundle-1".to_string(),
            story_id: StoryId::new(),
            story_version: 7,
            run_mode: RunMode::Deterministic,
            scenario_id: "scenario-1".to_string(),
            created_at: "2026-07-11T00:00:00Z".to_string(),
            git_sha: "0123456789abcdef".to_string(),
            source_dirty: false,
            chain_head: Sha256Digest::from_bytes(b"event chain"),
            final_frame_hash: Sha256Digest::from_bytes(b"final frame"),
            signature_algorithm: "ed25519".to_string(),
            key_id: "review-key-1".to_string(),
            files,
            verification: BundleVerificationSummary {
                event_chain_verified: true,
                report_claims_verified: true,
                scenario_assertions_verified: None,
                evidence_status: EvidenceStatus::Verified,
            },
        }
    }

    #[test]
    fn bundle_file_digest_validates_path_and_digest() {
        let digest = Sha256Digest::from_bytes(b"payload").as_str().to_string();

        assert!(BundleFileDigest::new("story.json", 7, digest.clone()).is_ok());
        for invalid_path in [
            "",
            "/story.json",
            "../story.json",
            "payload/../story.json",
            "payload//story.json",
            "C:/story.json",
            r"payload\story.json",
        ] {
            assert!(
                BundleFileDigest::new(invalid_path, 7, digest.clone()).is_err(),
                "path must be rejected: {invalid_path:?}"
            );
            assert!(
                serde_json::from_value::<BundleFileDigest>(json!({
                    "relative_path": invalid_path,
                    "bytes": 7,
                    "sha256": digest,
                }))
                .is_err(),
                "deserialization must reject path: {invalid_path:?}"
            );
        }
        assert!(BundleFileDigest::new("story.json", 7, "sha256:not-a-digest").is_err());
        assert!(
            serde_json::from_value::<BundleFileDigest>(json!({
                "relative_path": "story.json",
                "bytes": 7,
                "sha256": "sha256:not-a-digest",
            }))
            .is_err()
        );
    }

    #[test]
    fn signature_material_sorts_files_and_has_no_embedded_signature() {
        let unsorted = manifest(vec![file("z.json", b"z"), file("a.json", b"a")]);
        let sorted = manifest(vec![file("a.json", b"a"), file("z.json", b"z")]);
        let mut sorted = sorted;
        sorted.story_id = unsorted.story_id;

        assert_eq!(
            unsorted.signature_material().unwrap(),
            sorted.signature_material().unwrap()
        );
        assert_eq!(unsorted.files[0].relative_path().as_str(), "z.json");

        let material: Value =
            serde_json::from_slice(&unsorted.signature_material().unwrap()).unwrap();
        assert_eq!(material["files"][0]["relative_path"], "a.json");
        assert_eq!(material["files"][1]["relative_path"], "z.json");
        assert!(material.get("signature").is_none());
    }

    #[test]
    fn bundle_wire_contract_rejects_unknown_fields() {
        let manifest = manifest(vec![file("story.json", b"story")]);
        let mut root = serde_json::to_value(&manifest).unwrap();
        root.as_object_mut().unwrap().insert(
            "signature".to_string(),
            Value::String("detached".to_string()),
        );
        assert!(serde_json::from_value::<StoryBundleManifest>(root).is_err());

        let mut nested_file = serde_json::to_value(&manifest).unwrap();
        nested_file["files"][0].as_object_mut().unwrap().insert(
            "absolute_path".to_string(),
            Value::String("/tmp/story".to_string()),
        );
        assert!(serde_json::from_value::<StoryBundleManifest>(nested_file).is_err());

        let mut verification = serde_json::to_value(&manifest).unwrap();
        verification["verification"]
            .as_object_mut()
            .unwrap()
            .insert("trusted".to_string(), Value::Bool(true));
        assert!(serde_json::from_value::<StoryBundleManifest>(verification).is_err());
    }
}
