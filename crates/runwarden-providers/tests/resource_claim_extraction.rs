use runwarden_kernel::KernelProvider;
use runwarden_kernel::resource::{DataClass, FileAccess, MemoryAccess, ResourceClaim};
use runwarden_kernel::trace::Sha256Digest;
use runwarden_providers::catalog::{default_external_providers, default_first_party_providers};
use runwarden_providers::resource_claims::{ResourceExtractionContext, ResourceExtractorRegistry};
use serde_json::{Value, json};

fn context() -> ResourceExtractionContext {
    ResourceExtractionContext {
        filesystem_root: "contest-workspace".to_owned(),
        memory_namespace: "session-memory".to_owned(),
        knowledge_namespace: "curated-knowledge".to_owned(),
        default_classification: DataClass::Confidential,
    }
}

fn provider(provider_id: &str) -> KernelProvider {
    default_first_party_providers()
        .into_iter()
        .chain(default_external_providers())
        .find(|candidate| candidate.id == provider_id)
        .unwrap_or_else(|| panic!("provider catalog is missing {provider_id}"))
}

fn extract(provider_id: &str, action: &str, arguments: Value) -> ResourceClaim {
    ResourceExtractorRegistry::contest_default()
        .extract(&provider(provider_id), action, &arguments, &context())
        .unwrap_or_else(|error| {
            panic!("{provider_id}/{action} should extract a claim, got {error}")
        })
}

fn assert_extraction_error_contains(
    provider_id: &str,
    action: &str,
    arguments: Value,
    expected: &str,
) {
    let error = ResourceExtractorRegistry::contest_default()
        .extract(&provider(provider_id), action, &arguments, &context())
        .expect_err("invalid arguments must not produce a resource claim");
    let message = error.to_string().to_ascii_lowercase();
    assert!(
        message.contains(&expected.to_ascii_lowercase()),
        "expected {provider_id}/{action} error {message:?} to mention {expected:?}"
    );
}

#[test]
fn contest_provider_actions_extract_the_frozen_claim_kinds() {
    let cases = [
        (
            "external.mcp.filesystem.read_file",
            "read_file",
            json!({"path":"reports/q2.md"}),
            "file",
        ),
        (
            "external.mcp.filesystem.write_file",
            "write_file",
            json!({"path":"out/summary.md","content":"safe"}),
            "file",
        ),
        (
            "external.email.send",
            "send",
            json!({"to":["FINANCE@example.test"]}),
            "email",
        ),
        (
            "external.api.request",
            "request",
            json!({"method":"GET","url":"https://api.example.test/v1"}),
            "network",
        ),
        (
            "external.mcp.browser.open_page",
            "open_page",
            json!({"url":"https://docs.example.test/x"}),
            "network",
        ),
        (
            "external.memory.read",
            "read",
            json!({"key":"quarter"}),
            "memory",
        ),
        (
            "external.memory.write",
            "write",
            json!({"key":"quarter","value":"Q2"}),
            "memory",
        ),
        (
            "external.knowledge.read",
            "read",
            json!({"key":"policy"}),
            "memory",
        ),
        (
            "external.knowledge.write",
            "write",
            json!({"key":"policy","value":"x"}),
            "memory",
        ),
        (
            "runwarden.input.inspect",
            "inspect",
            json!({"input_text":"hello"}),
            "input_inspection",
        ),
    ];

    let registry = ResourceExtractorRegistry::contest_default();
    let extraction_context = context();
    for (provider_id, action, arguments, expected_kind) in cases {
        let claim = registry
            .extract(
                &provider(provider_id),
                action,
                &arguments,
                &extraction_context,
            )
            .unwrap_or_else(|error| {
                panic!("{provider_id}/{action} should extract a claim, got {error}")
            });
        let serialized = serde_json::to_value(claim).expect("claim serializes");
        assert_eq!(
            serialized["kind"], expected_kind,
            "wrong claim kind for {provider_id}/{action}"
        );
    }
}

#[test]
fn file_claims_bind_server_root_access_classification_and_normalized_path() {
    let read = extract(
        "external.mcp.filesystem.read_file",
        "read_file",
        json!({"path":"reports/./2026/q2.md"}),
    );
    let write = extract(
        "external.mcp.filesystem.write_file",
        "write_file",
        json!({"path":"out/summary.md","content":"safe"}),
    );

    match read {
        ResourceClaim::File {
            root,
            path,
            access,
            classification,
        } => {
            assert_eq!(root, "contest-workspace");
            assert_eq!(path.as_str(), "reports/2026/q2.md");
            assert_eq!(access, FileAccess::Read);
            assert_eq!(classification, DataClass::Confidential);
        }
        other => panic!("expected file claim, got {other:?}"),
    }

    match write {
        ResourceClaim::File {
            root,
            path,
            access,
            classification,
        } => {
            assert_eq!(root, "contest-workspace");
            assert_eq!(path.as_str(), "out/summary.md");
            assert_eq!(access, FileAccess::Write);
            assert_eq!(classification, DataClass::Confidential);
        }
        other => panic!("expected file claim, got {other:?}"),
    }
}

#[test]
fn file_claims_reject_ambiguous_or_escaping_paths() {
    for path in [
        "",
        "/etc/passwd",
        "../secrets.txt",
        "reports/../../secrets.txt",
        "reports\\q2.md",
        "reports//q2.md",
        "C:/secrets.txt",
        "reports/q2.md/",
    ] {
        assert_extraction_error_contains(
            "external.mcp.filesystem.read_file",
            "read_file",
            json!({"path": path}),
            "path",
        );
    }
}

#[test]
fn email_claims_ascii_normalize_domain_then_sort_and_deduplicate() {
    let claim = extract(
        "external.email.send",
        "send",
        json!({
            "to": [
                "finance@example.test",
                "Finance@EXAMPLE.test",
                "FINANCE@example.test",
                "Finance@example.test"
            ],
            "subject": "Q2",
            "body": "Review attached"
        }),
    );

    match claim {
        ResourceClaim::Email {
            recipients,
            classification,
        } => {
            assert_eq!(
                recipients,
                [
                    "FINANCE@example.test",
                    "Finance@example.test",
                    "finance@example.test"
                ]
            );
            assert_eq!(classification, DataClass::Confidential);
        }
        other => panic!("expected email claim, got {other:?}"),
    }
}

#[test]
fn email_claims_reject_empty_and_noncanonical_mailboxes() {
    assert_extraction_error_contains(
        "external.email.send",
        "send",
        json!({"to": []}),
        "recipient",
    );

    for mailbox in [
        "",
        "missing-at.example.test",
        "two@@example.test",
        " local@example.test",
        "local@example.test ",
        "local@",
        "@example.test",
        "local\n@example.test",
        "café@example.test",
    ] {
        assert_extraction_error_contains(
            "external.email.send",
            "send",
            json!({"to": [mailbox]}),
            "recipient",
        );
    }
}

#[test]
fn api_and_browser_claims_bind_canonical_origins_and_methods() {
    let api = extract(
        "external.api.request",
        "request",
        json!({
            "method":"post",
            "url":"https://API.EXAMPLE.test:443/v1/records?q=2#summary",
            "body":{"approved":true}
        }),
    );
    let browser = extract(
        "external.mcp.browser.open_page",
        "open_page",
        json!({"url":"http://Docs.Example.test:8080/guide?q=claim#part"}),
    );

    match api {
        ResourceClaim::Network {
            method,
            origin,
            classification,
        } => {
            assert_eq!(method, "POST");
            assert_eq!(origin, "https://api.example.test");
            assert_eq!(classification, DataClass::Confidential);
        }
        other => panic!("expected network claim, got {other:?}"),
    }

    match browser {
        ResourceClaim::Network {
            method,
            origin,
            classification,
        } => {
            assert_eq!(method, "GET");
            assert_eq!(origin, "http://docs.example.test:8080");
            assert_eq!(classification, DataClass::Confidential);
        }
        other => panic!("expected network claim, got {other:?}"),
    }
}

#[test]
fn network_claims_reject_malformed_unsafe_or_ambiguous_urls_and_methods() {
    for (method, url) in [
        ("GET", "not a url"),
        ("GET", "file:///etc/passwd"),
        ("GET", "https://user:password@example.test/v1"),
        ("GET", "https://"),
        ("G ET", "https://api.example.test/v1"),
        ("", "https://api.example.test/v1"),
    ] {
        assert_extraction_error_contains(
            "external.api.request",
            "request",
            json!({"method": method, "url": url}),
            if url.starts_with("https://api.example.test") {
                "method"
            } else {
                "url"
            },
        );
    }
}

#[test]
fn store_claims_bind_server_namespaces_keys_and_access_modes() {
    let cases = [
        (
            "external.memory.read",
            "read",
            json!({"key":"quarter"}),
            "session-memory",
            MemoryAccess::Read,
        ),
        (
            "external.memory.write",
            "write",
            json!({"key":"quarter","value":"Q2"}),
            "session-memory",
            MemoryAccess::Write,
        ),
        (
            "external.knowledge.read",
            "read",
            json!({"key":"policy"}),
            "curated-knowledge",
            MemoryAccess::Read,
        ),
        (
            "external.knowledge.write",
            "write",
            json!({"key":"policy","value":"x"}),
            "curated-knowledge",
            MemoryAccess::Write,
        ),
    ];

    for (provider_id, action, arguments, expected_namespace, expected_access) in cases {
        match extract(provider_id, action, arguments) {
            ResourceClaim::Memory {
                namespace,
                key,
                access,
            } => {
                assert_eq!(namespace, expected_namespace);
                assert!(!key.is_empty());
                assert_eq!(access, expected_access);
            }
            other => panic!("expected memory claim, got {other:?}"),
        }
    }
}

#[test]
fn input_inspection_claim_hashes_exact_input_bytes() {
    let claim = extract(
        "runwarden.input.inspect",
        "inspect",
        json!({"input_text":"hello"}),
    );

    match claim {
        ResourceClaim::InputInspection {
            source,
            content_hash,
            classification,
        } => {
            assert_eq!(source, "tool_input", "input source must be kernel-derived");
            assert_eq!(content_hash, Sha256Digest::from_bytes(b"hello"));
            assert_eq!(classification, DataClass::Confidential);
        }
        other => panic!("expected input-inspection claim, got {other:?}"),
    }
}

#[test]
fn extractors_reject_missing_required_fields() {
    let cases = [
        (
            "external.mcp.filesystem.read_file",
            "read_file",
            json!({}),
            "path",
        ),
        (
            "external.mcp.filesystem.write_file",
            "write_file",
            json!({"path":"out/summary.md"}),
            "content",
        ),
        ("external.email.send", "send", json!({}), "to"),
        (
            "external.api.request",
            "request",
            json!({"url":"https://api.example.test/v1"}),
            "method",
        ),
        (
            "external.api.request",
            "request",
            json!({"method":"GET"}),
            "url",
        ),
        (
            "external.mcp.browser.open_page",
            "open_page",
            json!({}),
            "url",
        ),
        ("external.memory.read", "read", json!({}), "key"),
        (
            "external.memory.write",
            "write",
            json!({"key":"quarter"}),
            "value",
        ),
        ("external.knowledge.read", "read", json!({}), "key"),
        (
            "external.knowledge.write",
            "write",
            json!({"key":"policy"}),
            "value",
        ),
        (
            "runwarden.input.inspect",
            "inspect",
            json!({}),
            "input_text",
        ),
    ];

    for (provider_id, action, arguments, missing_field) in cases {
        assert_extraction_error_contains(provider_id, action, arguments, missing_field);
    }
}

#[test]
fn extractors_reject_unknown_fields_instead_of_silently_ignoring_them() {
    let cases = [
        (
            "external.mcp.filesystem.read_file",
            "read_file",
            json!({"path":"reports/q2.md","unexpected":true}),
        ),
        (
            "external.mcp.filesystem.write_file",
            "write_file",
            json!({"path":"out/summary.md","content":"safe","unexpected":true}),
        ),
        (
            "external.email.send",
            "send",
            json!({"to":["finance@example.test"],"unexpected":true}),
        ),
        (
            "external.api.request",
            "request",
            json!({"method":"GET","url":"https://api.example.test/v1","unexpected":true}),
        ),
        (
            "external.mcp.browser.open_page",
            "open_page",
            json!({"url":"https://docs.example.test/x","unexpected":true}),
        ),
        (
            "external.memory.read",
            "read",
            json!({"key":"quarter","unexpected":true}),
        ),
        (
            "external.memory.write",
            "write",
            json!({"key":"quarter","value":"Q2","unexpected":true}),
        ),
        (
            "external.knowledge.read",
            "read",
            json!({"key":"policy","unexpected":true}),
        ),
        (
            "external.knowledge.write",
            "write",
            json!({"key":"policy","value":"x","unexpected":true}),
        ),
        (
            "runwarden.input.inspect",
            "inspect",
            json!({"input_text":"hello","unexpected":true}),
        ),
    ];

    for (provider_id, action, arguments) in cases {
        assert_extraction_error_contains(provider_id, action, arguments, "unexpected");
    }
}

#[test]
fn policy_like_agent_fields_are_always_reserved() {
    for field in ["root", "namespace", "classification"] {
        let mut arguments = json!({"path":"reports/q2.md"});
        arguments
            .as_object_mut()
            .expect("object")
            .insert(field.to_owned(), json!("attacker-controlled"));
        assert_extraction_error_contains(
            "external.mcp.filesystem.read_file",
            "read_file",
            arguments,
            field,
        );
    }

    assert_extraction_error_contains(
        "external.mcp.filesystem.read_file",
        "read_file",
        json!({
            "path": "reports/q2.md",
            "root": "/etc",
            "classification": "public",
            "namespace": "admin"
        }),
        "reserved",
    );
}

#[test]
fn extraction_rejects_non_objects_wrong_types_and_invalid_trusted_context() {
    let registry = ResourceExtractorRegistry::contest_default();
    let file_provider = provider("external.mcp.filesystem.read_file");
    let email_provider = provider("external.email.send");

    for arguments in [json!(null), json!([]), json!("reports/q2.md")] {
        let error = registry
            .extract(&file_provider, "read_file", &arguments, &context())
            .expect_err("non-object arguments must fail closed");
        assert_eq!(error.code(), "arguments_not_object");
    }

    for arguments in [
        json!({"path": 7}),
        json!({"path":"reports/q2.md","content":false}),
    ] {
        let target = if arguments.get("content").is_some() {
            provider("external.mcp.filesystem.write_file")
        } else {
            file_provider.clone()
        };
        let action = if arguments.get("content").is_some() {
            "write_file"
        } else {
            "read_file"
        };
        assert!(
            registry
                .extract(&target, action, &arguments, &context())
                .is_err()
        );
    }

    let mut invalid_context = context();
    invalid_context.filesystem_root.clear();
    let error = registry
        .extract(
            &file_provider,
            "read_file",
            &json!({"path":"reports/q2.md"}),
            &invalid_context,
        )
        .expect_err("empty server-owned root must fail closed");
    assert_eq!(error.code(), "invalid_context");

    let error = registry
        .extract(
            &email_provider,
            "send",
            &json!({"to":"finance@example.test"}),
            &context(),
        )
        .expect_err("legacy scalar recipient form must not be ambiguous");
    assert_eq!(error.code(), "invalid_field_type");
}

#[test]
fn input_source_and_execution_controls_cannot_be_forged() {
    for field in [
        "input_source",
        "approval_id",
        "budget_charge",
        "execution_permit",
        "policy_snapshot_hash",
        "runtime",
        "cwd",
        "env",
        "transport",
        "command",
    ] {
        let mut arguments = json!({"input_text":"hello"});
        arguments
            .as_object_mut()
            .expect("object")
            .insert(field.to_owned(), json!("attacker-controlled"));
        let error = ResourceExtractorRegistry::contest_default()
            .extract(
                &provider("runwarden.input.inspect"),
                "inspect",
                &arguments,
                &context(),
            )
            .expect_err("caller-supplied provenance or execution controls must fail");
        assert!(matches!(error.code(), "reserved_field" | "unknown_field"));
    }
}

#[test]
fn canonical_provider_contract_cannot_be_replaced_by_same_id() {
    let mut forged = provider("external.email.send");
    forged.risk = runwarden_kernel::ProviderRisk::Low;
    let error = ResourceExtractorRegistry::contest_default()
        .extract(
            &forged,
            "send",
            &json!({"to":["finance@example.test"]}),
            &context(),
        )
        .expect_err("same-id provider contract forgery must fail closed");
    assert_eq!(error.code(), "provider_contract_mismatch");
}

#[test]
fn unsupported_providers_and_actions_never_fall_back_to_opaque_claims() {
    assert_extraction_error_contains("runwarden.trace.verify", "verify", json!({}), "provider");
    assert_extraction_error_contains(
        "external.mcp.filesystem.read_file",
        "delete_file",
        json!({"path":"reports/q2.md"}),
        "action",
    );
}
