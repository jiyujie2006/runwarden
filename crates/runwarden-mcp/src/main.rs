use std::io::{BufRead, BufReader, Write};

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
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(None);
    }

    if !line.starts_with("Content-Length:") {
        let mut rest = String::new();
        reader.read_to_string(&mut rest)?;
        line.push_str(&rest);
        return Ok(Some(line));
    }

    let mut content_length = line
        .strip_prefix("Content-Length:")
        .and_then(|value| value.trim().parse::<usize>().ok());
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            anyhow::bail!("MCP frame ended before header terminator");
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
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body)?;
    String::from_utf8(body)
        .map(Some)
        .map_err(|err| anyhow::anyhow!("MCP frame body is not UTF-8: {err}"))
}
