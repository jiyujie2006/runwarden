use std::io::{BufRead, BufReader, Write};

const MAX_STDIO_FRAME_BYTES: usize = 1_048_576;
const MAX_STDIO_HEADER_BYTES: usize = 16 * 1024;

fn main() -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    while let Some(body) = read_next_body(&mut reader)? {
        if body.trim().is_empty() {
            continue;
        }
        let Some(response) = runwarden_mcp::handle_jsonrpc_message(&body)? else {
            continue;
        };
        let response_body = serde_json::to_string(&response)?;
        write!(
            stdout,
            "Content-Length: {}\r\n\r\n{}",
            response_body.len(),
            response_body
        )?;
        stdout.flush()?;
    }
    Ok(())
}

fn read_next_body<R: BufRead>(reader: &mut R) -> anyhow::Result<Option<String>> {
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
            return Ok(Some(line));
        }
        return read_remaining_raw_body(reader, line).map(Some);
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
    String::from_utf8(body)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("MCP frame body is not UTF-8: {err}"))
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
