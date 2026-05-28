use std::io::{Read, Write};

fn main() -> anyhow::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    if input.trim().is_empty() {
        return Ok(());
    }

    let response = runwarden_mcp::handle_stdio_payload(&input)?;
    std::io::stdout().write_all(response.as_bytes())?;
    Ok(())
}
