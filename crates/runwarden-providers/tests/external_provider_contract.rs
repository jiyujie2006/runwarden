use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use runwarden_kernel::{ProviderKind, ProviderRisk};
use runwarden_providers::external::{
    ExternalMcpAdapterRequest, certify_external_provider_manifest, execute_external_mcp_adapter,
    load_provider_manifest,
};
use tempfile::tempdir;

#[test]
fn external_mcp_manifest_certifies_identity_permissions_and_schema_pin() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "stdio",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["https://example.com"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");

    assert_eq!(manifest.kind, ProviderKind::Mcp);
    assert_eq!(manifest.risk, ProviderRisk::NetworkActive);

    let report = certify_external_provider_manifest(&manifest);

    assert!(report.passed, "{report:?}");
    assert!(report.findings.is_empty());
    assert_eq!(
        report.contract.provider.id,
        "external.mcp.browser.open_page"
    );
    assert_eq!(report.side_effect_executed, false);
}

#[test]
fn external_shell_manifest_requires_command_allowlist_and_working_root() {
    let manifest = load_provider_manifest(
        r#"{
          "schema_version": "1",
          "provider_id": "external.shell.command",
          "provider_class": "external",
          "kind": "shell",
          "risk": "destructive",
          "side_effects": ["process_spawn", "destructive"],
          "declared_permissions": ["process_spawn"],
          "schema_pin": {
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {"type": "object"}
          },
          "observed_schema": {"type": "object"}
        }"#,
    )
    .expect("manifest parses");

    let report = certify_external_provider_manifest(&manifest);

    assert!(!report.passed);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding == "shell_command_allowlist_required")
    );
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding == "shell_working_root_required")
    );
    assert_eq!(report.side_effect_executed, false);
}

#[test]
fn external_mcp_stdio_adapter_executes_framed_downstream_call() {
    let dir = tempdir().expect("tempdir");
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["process_spawn"],
          "transport": "stdio",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["process_spawn"],
          "allowed_origins": [],
          "command_allowlist": ["cat"],
          "working_root": "{}",
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#,
        dir.path().display()
    ))
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("stdio".to_string()),
        command: Some("cat".to_string()),
        cwd: Some(dir.path().to_path_buf()),
        request: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "open_page",
            "params": {"url": "https://example.com"}
        }),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_external_mcp_adapter(&manifest, &request, Some(dir.path()));

    assert_eq!(result["decision"], "allowed");
    assert_eq!(result["execution_status"], "completed");
    assert_eq!(result["side_effect_executed"], true);
    assert_eq!(result["transport"], "stdio");
    assert!(
        result["stdout"]
            .as_str()
            .expect("stdout string")
            .contains("Content-Length:")
    );
}

#[test]
fn external_mcp_http_adapter_posts_to_allowed_origin() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
    let addr = listener.local_addr().expect("local addr");
    let origin = format!("http://{addr}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = [0_u8; 2048];
        let size = stream.read(&mut request).expect("read request");
        let request = String::from_utf8_lossy(&request[..size]);
        assert!(request.starts_with("POST /mcp HTTP/1.1"));
        assert!(request.contains("\"method\":\"open_page\""));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}",
            )
            .expect("write response");
    });
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "http",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["{origin}"],
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#
    ))
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("http".to_string()),
        url: Some(format!("{origin}/mcp")),
        request: serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "open_page",
            "params": {"url": "https://example.com"}
        }),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_external_mcp_adapter(&manifest, &request, None);

    handle.join().expect("server thread");
    assert_eq!(result["decision"], "allowed");
    assert_eq!(result["execution_status"], "completed");
    assert_eq!(result["transport"], "http");
    assert_eq!(result["http_status"], 200);
    assert_eq!(result["side_effect_executed"], true);
}

#[test]
fn external_mcp_sse_adapter_reads_allowed_event_stream() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local test server");
    let addr = listener.local_addr().expect("local addr");
    let origin = format!("http://{addr}");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = [0_u8; 2048];
        let size = stream.read(&mut request).expect("read request");
        let request = String::from_utf8_lossy(&request[..size]);
        assert!(request.starts_with("GET /events HTTP/1.1"));
        assert!(request.contains("Accept: text/event-stream"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\nevent: message\ndata: {\"ready\":true}\n\n",
            )
            .expect("write response");
    });
    let manifest = load_provider_manifest(&format!(
        r#"{{
          "schema_version": "1",
          "provider_id": "external.mcp.browser.open_page",
          "provider_class": "external",
          "kind": "mcp",
          "risk": "network_active",
          "side_effects": ["network"],
          "transport": "sse",
          "downstream_identity": "browser-mcp",
          "tool_identity": "open_page",
          "declared_permissions": ["network"],
          "allowed_origins": ["{origin}"],
          "schema_pin": {{
            "algorithm": "sha256",
            "digest": "sha256:a2c799262a3ce3c19ef5cdd983bf3d12b43ab3c426227091b909dcb7054738c0",
            "schema": {{"type": "object"}}
          }},
          "observed_schema": {{"type": "object"}}
        }}"#
    ))
    .expect("manifest parses");
    let request = ExternalMcpAdapterRequest {
        transport: Some("sse".to_string()),
        url: Some(format!("{origin}/events")),
        ..ExternalMcpAdapterRequest::default()
    };

    let result = execute_external_mcp_adapter(&manifest, &request, None);

    handle.join().expect("server thread");
    assert_eq!(result["decision"], "allowed");
    assert_eq!(result["execution_status"], "completed");
    assert_eq!(result["transport"], "sse");
    assert_eq!(result["event"], "{\"ready\":true}");
    assert_eq!(result["side_effect_executed"], true);
}
