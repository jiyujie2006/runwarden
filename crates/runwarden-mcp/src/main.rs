use std::io::{BufRead, BufReader, Write};

use runwarden_kernel::evidence::hex_sha256;
use serde_json::{Value, json};

const MAX_STDIO_FRAME_BYTES: usize = 1_048_576;
const MAX_STDIO_HEADER_BYTES: usize = 16 * 1024;

fn main() -> anyhow::Result<()> {
    // Capture the launcher-owned logical identity exactly once at process
    // startup. Model requests cannot mutate it between calls.
    let identity = runwarden_mcp::ServerIdentity::from_process_env()?;
    let debug_path = std::env::var("RUNWARDEN_MCP_DEBUG_FILE").ok();
    let debug = |record: Value| {
        if let Some(path) = &debug_path {
            let _ = append_debug_record(std::path::Path::new(path), &record);
        }
    };
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    while let Some((body, framed)) = read_next_body(&mut reader)? {
        debug(debug_message_metadata("request", framed, &body));
        if body.trim().is_empty() {
            continue;
        }
        let Some(response) = runwarden_mcp::handle_jsonrpc_message_for_identity(&body, &identity)?
        else {
            continue;
        };
        let response_body = serde_json::to_string(&response)?;
        debug(debug_message_metadata("response", framed, &response_body));
        if framed {
            write!(
                stdout,
                "Content-Length: {}\r\n\r\n{}",
                response_body.len(),
                response_body
            )?;
        } else {
            // Client used newline-delimited JSON (MCP stdio, e.g. opencode);
            // respond in kind so NDJSON-only clients can parse the response.
            stdout.write_all(response_body.as_bytes())?;
            stdout.write_all(b"\n")?;
        }
        stdout.flush()?;
    }
    debug(json!({
        "schema_version": "runwarden.mcp-debug-metadata.v1",
        "direction": "eof"
    }));
    Ok(())
}

fn debug_message_metadata(direction: &str, framed: bool, body: &str) -> Value {
    let parsed = serde_json::from_str::<Value>(body).ok();
    let mut metadata = json!({
        "schema_version": "runwarden.mcp-debug-metadata.v1",
        "direction": direction,
        "transport": if framed { "content_length" } else { "ndjson" },
        "bytes": body.len(),
        "sha256": hex_sha256(body.as_bytes()),
        "json_valid": parsed.is_some()
    });
    if let Some(parsed) = parsed.as_ref() {
        metadata["id_type"] = json!(json_type_name(parsed.get("id").unwrap_or(&Value::Null)));
        if direction == "request" {
            metadata["method"] = json!(safe_jsonrpc_method(
                parsed.get("method").and_then(Value::as_str)
            ));
            metadata["tool"] = json!(safe_tool_name(
                parsed
                    .get("params")
                    .and_then(|params| params.get("name"))
                    .and_then(Value::as_str)
            ));
        } else {
            metadata["response_shape"] = json!(if parsed.get("error").is_some() {
                "jsonrpc_error"
            } else if parsed.get("result").is_some() {
                "jsonrpc_result"
            } else {
                "other"
            });
            metadata["tool_is_error"] = parsed
                .get("result")
                .and_then(|result| result.get("isError"))
                .cloned()
                .unwrap_or(Value::Null);
        }
    }
    metadata
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn safe_jsonrpc_method(method: Option<&str>) -> &'static str {
    match method {
        Some("initialize") => "initialize",
        Some("initialized") => "initialized",
        Some("tools/list") => "tools/list",
        Some("tools/call") => "tools/call",
        Some(_) => "other",
        None => "missing",
    }
}

fn safe_tool_name(tool: Option<&str>) -> &'static str {
    match tool {
        Some("runwarden.agent.bootstrap") => "runwarden.agent.bootstrap",
        Some("runwarden.provider.call") => "runwarden.provider.call",
        Some("runwarden.provider.list") => "runwarden.provider.list",
        Some("runwarden.provider.status") => "runwarden.provider.status",
        Some("runwarden.trace.verify") => "runwarden.trace.verify",
        Some("runwarden.trace.export") => "runwarden.trace.export",
        Some("runwarden.report.lint") => "runwarden.report.lint",
        Some("runwarden.report.render") => "runwarden.report.render",
        Some(_) => "other",
        None => "missing",
    }
}

fn append_debug_record(path: &std::path::Path, record: &Value) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn read_next_body<R: BufRead>(reader: &mut R) -> anyhow::Result<Option<(String, bool)>> {
    let Some(mut line) = read_limited_line(
        reader,
        MAX_STDIO_FRAME_BYTES,
        "MCP raw payload exceeds maximum size",
    )?
    else {
        return Ok(None);
    };

    if !line.starts_with("Content-Length:") {
        if serde_json::from_str::<serde_json::Value>(&line).is_ok() {
            return Ok(Some((line, false)));
        }
        let body = read_remaining_raw_body(reader, line)?;
        return Ok(Some((body, false)));
    }

    let mut header_bytes = line.len();
    if header_bytes > MAX_STDIO_HEADER_BYTES {
        anyhow::bail!("MCP frame headers exceed maximum size");
    }
    let mut content_length = line
        .strip_prefix("Content-Length:")
        .and_then(|value| value.trim().parse::<usize>().ok());
    loop {
        let remaining_header_bytes = MAX_STDIO_HEADER_BYTES.saturating_sub(header_bytes);
        let Some(next_line) = read_limited_line(
            reader,
            remaining_header_bytes,
            "MCP frame headers exceed maximum size",
        )?
        else {
            anyhow::bail!("MCP frame ended before header terminator");
        };
        line = next_line;
        header_bytes += line.len();
        if header_bytes > MAX_STDIO_HEADER_BYTES {
            anyhow::bail!("MCP frame headers exceed maximum size");
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }

    let content_length =
        content_length.ok_or_else(|| anyhow::anyhow!("MCP frame is missing Content-Length"))?;
    if content_length > MAX_STDIO_FRAME_BYTES {
        anyhow::bail!("MCP frame Content-Length exceeds maximum size");
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    let body = String::from_utf8(body)
        .map_err(|err| anyhow::anyhow!("MCP frame body is not UTF-8: {err}"))?;
    Ok(Some((body, true)))
}

fn read_remaining_raw_body<R: BufRead>(
    reader: &mut R,
    first_line: String,
) -> anyhow::Result<String> {
    let mut body = first_line.into_bytes();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        if body.len().saturating_add(available.len()) > MAX_STDIO_FRAME_BYTES {
            anyhow::bail!("MCP raw payload exceeds maximum size");
        }
        let consumed = available.len();
        body.extend_from_slice(available);
        reader.consume(consumed);
    }
    String::from_utf8(body).map_err(|err| anyhow::anyhow!("MCP raw payload is not UTF-8: {err}"))
}

fn read_limited_line<R: BufRead>(
    reader: &mut R,
    limit: usize,
    limit_message: &str,
) -> anyhow::Result<Option<String>> {
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline_index = available.iter().position(|byte| *byte == b'\n');
        let take = newline_index.map_or(available.len(), |index| index + 1);
        if bytes.len().saturating_add(take) > limit {
            anyhow::bail!("{limit_message}");
        }
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline_index.is_some() {
            break;
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("MCP stdio line is not UTF-8: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn debug_metadata_never_contains_raw_jsonrpc_secrets() {
        let secret = "debug-secret-that-must-not-be-written";
        let request = json!({
            "jsonrpc": "2.0",
            "id": secret,
            "method": secret,
            "params": {
                "name": secret,
                "arguments": {"body": secret, "token": secret}
            }
        })
        .to_string();
        let metadata = debug_message_metadata("request", false, &request);
        let serialized = serde_json::to_string(&metadata).expect("debug metadata");
        assert!(!serialized.contains(secret));
        assert_eq!(metadata["method"], "other");
        assert_eq!(metadata["tool"], "other");
        assert_eq!(metadata["id_type"], "string");
        assert_eq!(metadata["bytes"], request.len());
    }

    #[test]
    fn debug_file_contains_only_metadata_and_is_private() {
        let root = std::env::temp_dir().join(format!(
            "runwarden-mcp-debug-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("debug test dir");
        let path = root.join("mcp-debug.jsonl");
        let secret = "response-secret-that-must-not-be-written";
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"structuredContent": {"output": secret}, "isError": false}
        })
        .to_string();
        let metadata = debug_message_metadata("response", true, &response);
        append_debug_record(&path, &metadata).expect("append debug metadata");
        let stored = std::fs::read_to_string(&path).expect("debug file");
        assert!(!stored.contains(secret));
        assert!(stored.contains("runwarden.mcp-debug-metadata.v1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("debug metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(root).expect("cleanup");
    }
}
