use anyhow::Result;
use clap::Parser;
use runwarden_llm_proxy::{Cli, serve};

fn main() -> Result<()> {
    serve(Cli::parse())
}
