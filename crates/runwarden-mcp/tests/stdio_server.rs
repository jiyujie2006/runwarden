mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use common::{INSTANCE_TOKEN, McpFixture};

#[test]
fn stdio_server_responds_to_framed_request_without_waiting_for_eof() {
    let fixture = McpFixture::new();
    let mut child = production_command(&fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn runwarden-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);
    let request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let frame = format!("Content-Length: {}\r\n\r\n{}", request.len(), request);

    stdin.write_all(frame.as_bytes()).expect("write frame");
    stdin.flush().expect("flush frame");

    let response = read_frame(&mut stdout);
    let _ = child.kill();
    let _ = child.wait();

    assert!(response.contains(r#""jsonrpc":"2.0""#));
    assert!(response.contains(r#""id":1"#));
    assert!(response.contains("runwarden-mcp"));
}

#[test]
fn stdio_server_accepts_one_ndjson_request_without_waiting_for_eof() {
    let fixture = McpFixture::new();
    let mut child = production_command(&fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn runwarden-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);
    let request = r#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{}}
"#;

    stdin.write_all(request.as_bytes()).expect("write request");
    stdin.flush().expect("flush request");

    // Raw (NDJSON) clients get a newline-delimited JSON response.
    let mut response = String::new();
    stdout
        .read_line(&mut response)
        .expect("read ndjson response line");
    let _ = child.kill();
    let _ = child.wait();

    assert!(response.contains(r#""jsonrpc":"2.0""#));
    assert!(response.contains(r#""id":7"#));
    assert!(response.contains("runwarden-mcp"));
}

#[test]
fn stdio_server_recovers_after_a_malformed_ndjson_request() {
    let fixture = McpFixture::new();
    let mut child = production_command(&fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn runwarden-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);

    stdin.write_all(b"{not-json\n").expect("write malformed");
    stdin.flush().expect("flush malformed");
    let mut malformed = String::new();
    let read = stdout
        .read_line(&mut malformed)
        .expect("read malformed response");
    assert_ne!(read, 0, "MCP process closed after malformed JSON");
    let malformed: serde_json::Value = serde_json::from_str(&malformed).expect("error response");
    assert_eq!(malformed["id"], serde_json::Value::Null);
    assert_eq!(malformed["error"]["code"], -32700);

    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"initialize\",\"params\":{}}\n")
        .expect("write valid request");
    stdin.flush().expect("flush valid request");
    let mut valid = String::new();
    let read = stdout.read_line(&mut valid).expect("read valid response");
    assert_ne!(read, 0, "MCP process closed before the next response");
    let valid: serde_json::Value = serde_json::from_str(&valid).expect("valid response");
    assert_eq!(valid["id"], 8);
    assert!(valid.get("result").is_some());

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn stdio_server_rejects_oversized_headers_before_body_allocation() {
    let fixture = McpFixture::new();
    let mut child = production_command(&fixture)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn runwarden-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let frame = format!("Content-Length: {}{}\r\n\r\n{{}}", 2, " ".repeat(17 * 1024));

    stdin.write_all(frame.as_bytes()).expect("write frame");
    drop(stdin);
    let status = child.wait().expect("wait");

    assert!(!status.success());
}

fn read_frame<R: BufRead>(reader: &mut R) -> String {
    let mut content_length = None;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).expect("read header");
        assert_ne!(
            read, 0,
            "MCP process closed stdout before completing a frame"
        );
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = Some(value.trim().parse::<usize>().expect("content length"));
        }
    }
    let length = content_length.expect("content length header");
    let mut body = vec![0; length];
    reader.read_exact(&mut body).expect("read body");
    String::from_utf8(body).expect("utf8 body")
}

fn production_command(fixture: &McpFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_runwarden-mcp"));
    command
        .env("RUNWARDEN_STATE_DIR", &fixture.state_dir)
        .env("RUNWARDEN_INSTANCE_TOKEN", INSTANCE_TOKEN)
        .env("RUNWARDEN_SANDBOX_ROOT", &fixture.sandbox_root)
        .env(
            "RUNWARDEN_TRUSTED_RUNTIME_ROOT",
            &fixture.trusted_runtime_root,
        )
        .env("RUNWARDEN_MCP_APPROVAL_WAIT_MS", "0");
    command
}
