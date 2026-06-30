use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn stdio_server_responds_to_framed_request_without_waiting_for_eof() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_runwarden-mcp"))
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
fn stdio_server_accepts_multiline_raw_payload_until_eof() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_runwarden-mcp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn runwarden-mcp");
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stdout = BufReader::new(stdout);
    let request = r#"{
  "jsonrpc": "2.0",
  "id": 7,
  "method": "initialize",
  "params": {}
}
"#;

    stdin.write_all(request.as_bytes()).expect("write request");
    drop(stdin);

    // Raw (NDJSON) clients get a newline-delimited JSON response.
    let mut response = String::new();
    stdout
        .read_line(&mut response)
        .expect("read ndjson response line");
    let status = child.wait().expect("wait");

    assert!(status.success());
    assert!(response.contains(r#""jsonrpc":"2.0""#));
    assert!(response.contains(r#""id":7"#));
    assert!(response.contains("runwarden-mcp"));
}

#[test]
fn stdio_server_rejects_oversized_headers_before_body_allocation() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_runwarden-mcp"))
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
        reader.read_line(&mut line).expect("read header");
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
