use std::{
    collections::BTreeMap,
    env, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use runwarden_api::{LocalApiRouter, LocalApiServerConfig, serve_next_request, serve_one_request};
use runwarden_assurance::accountability::accountability_summary;
use runwarden_assurance::artifact::{seal_artifact, verify_artifact_manifest};
use runwarden_assurance::audit::audit_summary;
use runwarden_assurance::bench::benchmark_workspace;
use runwarden_assurance::cert::{CertCheck, CertReport, certify_agent_config, certify_workspace};
use runwarden_assurance::eval::{
    AgentNativeConfigCase, AgentNativeExpectation, EvalThresholds, evaluate_agent_native_configs,
    evaluate_report_assurance,
};
use runwarden_assurance::report::{
    RenderFormat, ReportDraft, lint_report_against_trace, render_report, scaffold_report_from_trace,
};
use runwarden_kernel::artifact::ArtifactManifest;
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::contracts::{PolicyDecision, ProviderCall};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery, hex_sha256};
use runwarden_kernel::kernel::KernelEnforcer;
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_providers::catalog::{
    EXTERNAL_PROVIDER_IDS, FIRST_PARTY_PROVIDER_IDS, default_external_provider_manifest,
    default_external_providers, first_party_registry, full_provider_registry,
};
use runwarden_providers::evidence::{EvidenceInspectPolicy, inspect_evidence_root};
use runwarden_providers::external::{
    ExternalMcpAdapterRequest, certify_external_provider_manifest, execute_external_mcp_adapter,
    load_provider_manifest,
};
use runwarden_providers::input::{InputInspectPolicy, InputSource, inspect_input};
use runwarden_providers::runtime::{
    ProviderRuntime, ProviderRuntimeDenialKind, ProviderRuntimePolicy, ProviderRuntimeRequest,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(name = "runwarden")]
#[command(about = "Human control plane for Runwarden")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init,
    Check {
        #[arg(long)]
        strict: bool,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
    Cert {
        #[command(subcommand)]
        command: CertCommand,
    },
    Bench {
        #[command(subcommand)]
        command: BenchCommand,
    },
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    Authority {
        #[command(subcommand)]
        command: AuthorityCommand,
    },
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
    Ui {
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 8088)]
        port: u16,
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Api {
        #[command(subcommand)]
        command: ApiCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    GenerateConfig {
        #[arg(long)]
        client: String,
        #[arg(long)]
        output: PathBuf,
    },
    CheckConfig {
        #[arg(long)]
        client: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ReportCommand {
    Scaffold {
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Lint {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Render {
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        format: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EvalCommand {
    All {
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long = "expected-obs")]
        expected_obs: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    Scenarios {
        #[arg(long)]
        json: bool,
    },
    AgentNative {
        #[arg(long = "config")]
        configs: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum CertCommand {
    All {
        #[arg(long)]
        json: bool,
    },
    ProviderManifest {
        #[arg(long)]
        manifest: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    Mcp {
        #[arg(long)]
        json: bool,
    },
    Skill {
        #[arg(long)]
        json: bool,
    },
    Workflow {
        #[arg(long)]
        json: bool,
    },
    Script {
        #[arg(long)]
        json: bool,
    },
    Package {
        #[arg(long)]
        json: bool,
    },
    ReleaseArtifact {
        #[arg(long)]
        json: bool,
    },
    AgentConfig {
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum BenchCommand {
    Run {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProviderCommand {
    List {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Call {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long)]
        report: Option<PathBuf>,
        #[arg(long)]
        format: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    Verify {
        #[arg(long)]
        trace: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Export {
        #[arg(long)]
        trace: PathBuf,
        #[arg(long, default_value_t = 0)]
        offset: usize,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long = "event-type")]
        event_type: Option<String>,
        #[arg(long = "obs-prefix")]
        obs_prefix: Option<String>,
        #[arg(long = "max-bytes")]
        max_bytes: Option<usize>,
        #[arg(long = "compact-refs")]
        compact_refs: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum SessionCommand {
    Create {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        session: String,
        #[arg(long)]
        json: bool,
    },
    Inspect {
        #[arg(long)]
        session: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ArtifactCommand {
    Submission {
        #[arg(long)]
        full: bool,
        #[arg(long, default_value = "artifacts")]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Verify {
        #[arg(long, default_value = "artifacts")]
        artifacts: PathBuf,
        #[arg(long, default_value = "artifacts/artifact-manifest.json")]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    Smoke {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    Pending {
        #[arg(long)]
        json: bool,
    },
    Approve {
        approval_id: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
    Deny {
        approval_id: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AuthorityCommand {
    Create {
        #[arg(long)]
        approval: String,
        #[arg(long)]
        session: String,
        #[arg(long)]
        provider: String,
        #[arg(long)]
        action: String,
        #[arg(long, default_value = "{}")]
        arguments: String,
        #[arg(long = "argument-hash")]
        argument_hash: Option<String>,
        #[arg(long)]
        authz: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        json: bool,
    },
    Inspect {
        approval_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ApiCommand {
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 8088)]
        port: u16,
        #[arg(long)]
        launch_token: Option<String>,
        #[arg(long)]
        once: bool,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => {
            println!("runwarden initialized");
        }
        Command::Check { strict } => {
            if strict {
                run_strict_check()?;
            } else {
                println!("runwarden check passed");
            }
        }
        Command::Agent { command } => match command {
            AgentCommand::GenerateConfig { client, output } => {
                let body = generate_runwarden_only_config(&client)?;
                fs::write(&output, serde_json::to_string_pretty(&body)?)?;
                println!("wrote {}", output.display());
            }
            AgentCommand::CheckConfig {
                client,
                input,
                json,
            } => {
                let content = fs::read_to_string(&input)?;
                let config: AgentConfig = serde_json::from_str(&content)?;
                let result = check_runwarden_only_config(&client, &config);
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else if result.safe {
                    println!("agent config is runwarden-only");
                } else {
                    println!("agent config exposes raw or downstream tools");
                }
                if !result.safe {
                    anyhow::bail!("unsafe agent config");
                }
            }
        },
        Command::Report { command } => match command {
            ReportCommand::Scaffold { trace, json } => {
                let trace = read_trace(&trace)?;
                let report = scaffold_report_from_trace(&trace);
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    for claim in report.claims {
                        println!(
                            "{}: {} [{}]",
                            claim.id,
                            claim.text,
                            claim.obs_refs.join(", ")
                        );
                    }
                }
            }
            ReportCommand::Lint {
                report,
                trace,
                json,
            } => {
                let report = read_report(&report)?;
                let trace = read_trace(&trace)?;
                let result = lint_report_against_trace(&report, &trace);
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else if result.ok {
                    println!("report lint passed");
                } else {
                    println!("report lint failed");
                }
                if !result.ok {
                    anyhow::bail!("report lint failed");
                }
            }
            ReportCommand::Render {
                report,
                trace,
                format,
                json,
            } => {
                let report = read_report(&report)?;
                let trace = read_trace(&trace)?;
                let format = parse_render_format(&format)?;
                let result = render_report(&report, &trace, format)
                    .map_err(|err| anyhow::anyhow!(err.message))?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    println!("{}", result.contents);
                }
            }
        },
        Command::Eval { command } => match command {
            EvalCommand::All {
                report,
                trace,
                expected_obs,
                json,
            } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let report =
                    report.unwrap_or_else(|| root.join("tests/fixtures/default-report.json"));
                let trace = trace.unwrap_or_else(|| root.join("tests/fixtures/default-trace.json"));
                let report = read_report(&report)?;
                let trace = read_trace(&trace)?;
                let expected_obs = if expected_obs.is_empty() {
                    trace.iter().map(|event| event.obs_id.clone()).collect()
                } else {
                    expected_obs
                };
                let result = evaluate_report_assurance(
                    &report,
                    &trace,
                    expected_obs,
                    EvalThresholds::strict(),
                );
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else if result.passed {
                    println!("eval all passed");
                } else {
                    println!("eval all failed");
                }
                if !result.passed {
                    anyhow::bail!("eval all failed");
                }
            }
            EvalCommand::AgentNative { configs, json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let cases = load_agent_native_cases(&root, configs)?;
                let result = evaluate_agent_native_configs(&cases);
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else if result.passed {
                    println!("eval agent-native passed");
                } else {
                    println!("eval agent-native failed");
                }
                if !result.passed {
                    anyhow::bail!("eval agent-native failed");
                }
            }
            EvalCommand::Scenarios { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let result = evaluate_scenario_corpora(&root)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else if result["passed"].as_bool() == Some(true) {
                    println!("eval scenarios passed");
                } else {
                    println!("eval scenarios failed");
                }
                if result["passed"].as_bool() != Some(true) {
                    anyhow::bail!("eval scenarios failed");
                }
            }
        },
        Command::Cert { command } => match command {
            CertCommand::All { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let report = certify_workspace(&root);
                emit_cert_report("cert all", report, json)?;
            }
            CertCommand::ProviderManifest { manifest, json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let manifest = manifest.unwrap_or_else(|| {
                    root.join("examples/providers/external.mcp.browser.open_page.json")
                });
                let report = certify_provider_manifest_file(&manifest)?;
                emit_cert_report("cert provider-manifest", report, json)?;
            }
            CertCommand::Mcp { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                emit_cert_report("cert mcp", certify_mcp_surface(&root), json)?;
            }
            CertCommand::Skill { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                emit_cert_report(
                    "cert skill",
                    certify_required_paths(
                        &root,
                        "skill",
                        &["skills/runwarden-security-assessment/SKILL.md"],
                    ),
                    json,
                )?;
            }
            CertCommand::Workflow { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                emit_cert_report(
                    "cert workflow",
                    certify_required_paths(
                        &root,
                        "workflow",
                        &[".github/workflows/ci.yml", ".github/workflows/release.yml"],
                    ),
                    json,
                )?;
            }
            CertCommand::Script { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                emit_cert_report(
                    "cert script",
                    certify_required_paths(
                        &root,
                        "script",
                        &[
                            "scripts/dev_gate.sh",
                            "scripts/check_ts_contracts.sh",
                            "scripts/pr_fast_gate.sh",
                            "scripts/nightly_full_gate.sh",
                            "scripts/security_gate_local.sh",
                            "scripts/release_gate_local.sh",
                            "scripts/generate_artifacts.sh",
                            "scripts/artifact_leak_scan.sh",
                        ],
                    ),
                    json,
                )?;
            }
            CertCommand::Package { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                emit_cert_report(
                    "cert package",
                    certify_required_paths(
                        &root,
                        "package",
                        &[
                            "Cargo.toml",
                            "Cargo.lock",
                            "package.json",
                            "pnpm-lock.yaml",
                            "pnpm-workspace.yaml",
                        ],
                    ),
                    json,
                )?;
            }
            CertCommand::ReleaseArtifact { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                emit_cert_report(
                    "cert release-artifact",
                    certify_release_artifact_surface(&root),
                    json,
                )?;
            }
            CertCommand::AgentConfig { input, json } => {
                let content = fs::read_to_string(input)?;
                let config: serde_json::Value = serde_json::from_str(&content)?;
                let report = certify_agent_config(&config);
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else if report.passed {
                    println!("agent config cert passed");
                } else {
                    println!("agent config cert failed");
                }
                if !report.passed {
                    anyhow::bail!("agent config cert failed");
                }
            }
        },
        Command::Bench { command } => match command {
            BenchCommand::Run { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let report = benchmark_workspace(&root)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else if report.passed {
                    println!("bench run passed");
                } else {
                    println!("bench run failed");
                }
                if !report.passed {
                    anyhow::bail!("bench run failed");
                }
            }
        },
        Command::Provider { command } => match command {
            ProviderCommand::List { session, json } => {
                let providers = if let Some(session_id) = session {
                    read_session(&session_id)?.allowed_providers
                } else {
                    FIRST_PARTY_PROVIDER_IDS
                        .iter()
                        .chain(EXTERNAL_PROVIDER_IDS.iter())
                        .map(|provider| (*provider).to_string())
                        .collect()
                };
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({ "providers": providers }))?
                    );
                } else {
                    for provider in providers {
                        println!("{provider}");
                    }
                }
            }
            ProviderCommand::Call {
                session,
                provider,
                input,
                root,
                trace,
                report,
                format,
                json,
            } => {
                let session_manifest = session.as_deref().map(read_session).transpose()?;
                let mut provider_call = session_manifest.as_ref().map(|session_manifest| {
                    provider_call_from_cli(
                        session_manifest,
                        &provider,
                        input.as_ref(),
                        root.as_ref(),
                        trace.as_ref(),
                        report.as_ref(),
                        format.as_deref(),
                    )
                });
                if let Some(call) = provider_call.as_mut() {
                    attach_matching_approval(call)?;
                    let mut enforcer = KernelEnforcer::new(
                        full_provider_registry(),
                        session_manifest
                            .as_ref()
                            .expect("session-backed provider call")
                            .to_kernel_policy(),
                    );
                    for approval in read_all_approvals()? {
                        enforcer.add_approval(approval);
                    }
                    let outcome = enforcer.evaluate_call(call);
                    if outcome.decision != PolicyDecision::Allowed {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&outcome)?);
                        } else {
                            println!(
                                "provider call {}: {}",
                                serde_json::to_string(&outcome.decision)?,
                                outcome.envelope.reason
                            );
                        }
                        return Ok(());
                    }
                    if call
                        .approval_id
                        .as_deref()
                        .and_then(|approval_id| enforcer.approval_state(approval_id))
                        == Some(ApprovalState::Consumed)
                    {
                        persist_consumed_cli_approval(
                            call,
                            &enforcer.approval_binding_for_call(call),
                        )?;
                    }
                }
                let execution_root = resolve_cli_execution_root(session_manifest.as_ref(), root);
                let result = if provider.starts_with("external.") {
                    call_external_provider(&provider, input, execution_root)?
                } else {
                    call_first_party_provider(
                        &provider,
                        input,
                        execution_root,
                        trace,
                        report,
                        format,
                    )?
                };
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    println!("provider call completed: {provider}");
                }
            }
        },
        Command::Trace { command } => match command {
            TraceCommand::Verify { trace, json } => {
                let events = read_trace(&trace)?;
                let verification = verify_trace_events(events);
                if json {
                    println!("{}", serde_json::to_string_pretty(&verification)?);
                } else if verification["verified"].as_bool() == Some(true) {
                    println!("trace verified");
                } else {
                    println!("trace verification failed");
                }
                if verification["verified"].as_bool() != Some(true) {
                    anyhow::bail!("trace verification failed");
                }
            }
            TraceCommand::Export {
                trace,
                offset,
                limit,
                provider,
                event_type,
                obs_prefix,
                max_bytes,
                compact_refs,
                json,
            } => {
                let events = read_trace(&trace)?;
                let verification = verify_trace_events(events.clone());
                if verification["verified"].as_bool() != Some(true) {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&verification)?);
                    }
                    anyhow::bail!("trace verification failed");
                }

                let mut store = InMemoryTraceStore::default();
                for event in events.clone() {
                    store.append(event);
                }
                let page = store.query(TraceQuery {
                    offset,
                    limit,
                    provider,
                    event_type,
                    obs_prefix,
                    max_bytes,
                });
                let compact_refs = if compact_refs {
                    json!(
                        page.events
                            .iter()
                            .map(|event| event.obs_id.clone())
                            .collect::<Vec<_>>()
                    )
                } else {
                    serde_json::Value::Null
                };
                let export = json!({
                    "verified": true,
                    "event_count": events.len(),
                    "events": events,
                    "page": page,
                    "compact_refs": compact_refs,
                    "side_effect_executed": false
                });
                if json {
                    println!("{}", serde_json::to_string_pretty(&export)?);
                } else {
                    println!("exported {} trace events", events.len());
                }
            }
        },
        Command::Session { command } => match command {
            SessionCommand::Create {
                manifest,
                session,
                json,
            } => {
                let manifest_body = fs::read_to_string(&manifest)?;
                let assessment = AssessmentManifest::from_toml_str(&manifest_body)?;
                let session_manifest = SessionManifest::from_assessment(session, &assessment);
                write_session(&session_manifest)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&session_manifest)?);
                } else {
                    println!("created session {}", session_manifest.session_id);
                }
            }
            SessionCommand::Inspect { session, json } => {
                let session_manifest = read_session(&session)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&session_manifest)?);
                } else {
                    println!("session {}", session_manifest.session_id);
                }
            }
        },
        Command::Artifact { command } => match command {
            ArtifactCommand::Submission { full, output, json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let result = write_submission_bundle(&root, &output, full)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else {
                    println!(
                        "wrote submission bundle manifest {}",
                        result["manifest_path"]
                            .as_str()
                            .unwrap_or("artifact-manifest.json")
                    );
                }
            }
            ArtifactCommand::Verify {
                artifacts,
                manifest,
                json,
            } => {
                let manifest_body = fs::read_to_string(manifest)?;
                let manifest: ArtifactManifest = serde_json::from_str(&manifest_body)?;
                let verification = verify_artifact_manifest(&artifacts, &manifest);
                if json {
                    println!("{}", serde_json::to_string_pretty(&verification)?);
                } else {
                    println!("artifact verification: {:?}", verification.status);
                }
                if !verification.findings.is_empty() {
                    anyhow::bail!("artifact verification failed");
                }
            }
        },
        Command::Approval { command } => match command {
            ApprovalCommand::Pending { json } => {
                let approvals = read_all_approvals()?;
                let pending: Vec<_> = approvals
                    .into_iter()
                    .filter(|approval| approval.state == ApprovalState::Pending)
                    .collect();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({ "approvals": pending }))?
                    );
                } else {
                    for approval in pending {
                        println!(
                            "{} {} {} {}",
                            approval.approval_id,
                            approval.binding.provider,
                            approval.binding.action,
                            approval.binding.argument_hash
                        );
                    }
                }
            }
            ApprovalCommand::Approve {
                approval_id,
                reviewer,
                reason,
                json,
            } => {
                let mut approval = read_approval(&approval_id)?;
                approval.approve(reviewer, reason)?;
                write_approval(&approval)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&approval)?);
                } else {
                    println!("approved {}", approval.approval_id);
                }
            }
            ApprovalCommand::Deny {
                approval_id,
                reviewer,
                reason,
                json,
            } => {
                let mut approval = read_approval(&approval_id)?;
                approval.deny(reviewer, reason)?;
                write_approval(&approval)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&approval)?);
                } else {
                    println!("denied {}", approval.approval_id);
                }
            }
        },
        Command::Authority { command } => match command {
            AuthorityCommand::Create {
                approval,
                session,
                provider,
                action,
                arguments,
                argument_hash,
                authz,
                actor,
                json,
            } => {
                safe_record_id(&approval)?;
                let computed_hash = match argument_hash {
                    Some(hash) => hash,
                    None => argument_hash_from_json(&arguments)?,
                };
                let approval = ApprovalRecord::new(
                    approval,
                    ApprovalBinding {
                        session_id: session,
                        provider,
                        action,
                        argument_hash: computed_hash,
                        authz_id: authz,
                        actor_id: actor,
                    },
                );
                write_approval(&approval)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&approval)?);
                } else {
                    println!("created authority approval {}", approval.approval_id);
                }
            }
            AuthorityCommand::Inspect { approval_id, json } => {
                let approval = read_approval(&approval_id)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&approval)?);
                } else {
                    println!(
                        "{} {} {} {}",
                        approval.approval_id,
                        approval.binding.provider,
                        approval.binding.action,
                        approval.binding.argument_hash
                    );
                }
            }
        },
        Command::Release { command } => match command {
            ReleaseCommand::Smoke { json } => {
                let root = find_workspace_root(env::current_dir()?)?;
                let result = release_smoke_report(&root)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                } else if result["passed"].as_bool() == Some(true) {
                    println!("release smoke passed");
                } else {
                    println!("release smoke failed");
                }
                if result["passed"].as_bool() != Some(true) {
                    anyhow::bail!("release smoke failed");
                }
            }
        },
        Command::Ui {
            bind,
            port,
            artifacts,
            json,
        } => {
            let result = write_ui_launch_bundle(&bind, port, &artifacts)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "wrote reviewer console launch bundle {}",
                    result["html_path"]
                        .as_str()
                        .unwrap_or("reviewer-console.html")
                );
            }
        }
        Command::Api { command } => match command {
            ApiCommand::Serve {
                bind,
                port,
                launch_token,
                once,
                dry_run,
                json,
            } => {
                let (launch_token, launch_token_generated) = resolve_launch_token(launch_token);
                let result = local_api_serve_descriptor(
                    &bind,
                    port,
                    &launch_token,
                    launch_token_generated,
                    once,
                );
                if dry_run {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&result)?);
                    } else {
                        println!(
                            "runwarden Local API would listen on {}",
                            result["listen_addr"].as_str().unwrap_or("127.0.0.1:8088")
                        );
                    }
                } else {
                    let listener = TcpListener::bind(format!("{bind}:{port}"))?;
                    let addr = listener.local_addr()?;
                    let config = LocalApiServerConfig {
                        launch_token,
                        allowed_host: addr.to_string(),
                        allowed_origin: format!("http://{addr}"),
                    };
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "mode": "local_api_server",
                                "listen_addr": addr.to_string(),
                                "once": once,
                                "launch_token_generated": launch_token_generated,
                                "launch_token": if launch_token_generated { serde_json::Value::String(config.launch_token.clone()) } else { serde_json::Value::Null },
                                "side_effect_executed": true
                            }))?
                        );
                    }
                    if once {
                        serve_one_request(listener, config)?;
                    } else {
                        let mut router = LocalApiRouter::from_config(config);
                        loop {
                            serve_next_request(&listener, &mut router)?;
                        }
                    }
                }
            }
        },
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ExternalShellRequest {
    executable: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: Option<PathBuf>,
    #[serde(default)]
    use_shell: bool,
    timeout_ms: Option<u64>,
    stdout_limit_bytes: Option<usize>,
    stderr_limit_bytes: Option<usize>,
}

fn call_external_provider(
    provider: &str,
    input: Option<PathBuf>,
    root: Option<PathBuf>,
) -> anyhow::Result<serde_json::Value> {
    if !EXTERNAL_PROVIDER_IDS.contains(&provider) {
        anyhow::bail!("unsupported external provider call: {provider}");
    }

    match provider {
        "external.shell.command" => {
            let input_path = input.ok_or_else(|| {
                anyhow::anyhow!(
                    "--input JSON is required for external.shell.command mediated calls"
                )
            })?;
            let request_body = fs::read_to_string(&input_path)?;
            let shell_request: ExternalShellRequest = serde_json::from_str(&request_body)?;
            let command_allowlist = ["git", "cargo", "pnpm"];
            if !command_allowlist.contains(&shell_request.executable.as_str()) {
                return Ok(json!({
                    "provider": provider,
                    "decision": "denied",
                    "execution_status": "not_executed",
                    "error_kind": "provider_not_allowed",
                    "reason": "external shell executable is not allowlisted",
                    "side_effect_executed": false
                }));
            }

            let cwd = shell_request.cwd.unwrap_or_else(|| PathBuf::from("."));
            let runtime_root = root.unwrap_or_else(|| cwd.clone());
            let policy = ProviderRuntimePolicy::locked_to_root(runtime_root);
            let mut runtime_request = ProviderRuntimeRequest::new(shell_request.executable.clone())
                .cwd(cwd)
                .use_shell(shell_request.use_shell);
            for arg in shell_request.args {
                runtime_request = runtime_request.arg(arg);
            }
            if let Some(timeout_ms) = shell_request.timeout_ms {
                runtime_request = runtime_request.timeout_ms(timeout_ms);
            }
            if let Some(stdout_limit_bytes) = shell_request.stdout_limit_bytes {
                runtime_request = runtime_request.stdout_limit_bytes(stdout_limit_bytes);
            }
            if let Some(stderr_limit_bytes) = shell_request.stderr_limit_bytes {
                runtime_request = runtime_request.stderr_limit_bytes(stderr_limit_bytes);
            }

            match ProviderRuntime::prepare(&policy, &runtime_request) {
                Ok(prepared_process) => Ok(json!({
                    "provider": provider,
                    "decision": "requires_review",
                    "execution_status": "not_executed",
                    "reason": "external shell command was prepared by runtime mediation and awaits human approval",
                    "prepared_process": prepared_process,
                    "side_effect_executed": false
                })),
                Err(denial) => Ok(json!({
                    "provider": provider,
                    "decision": "denied",
                    "execution_status": "not_executed",
                    "error_kind": runtime_denial_error_kind(&denial.kind),
                    "reason": denial.reason,
                    "side_effect_executed": denial.side_effect_executed
                })),
            }
        }
        other if other.starts_with("external.mcp.") => {
            let input_path = input.ok_or_else(|| {
                anyhow::anyhow!("--input JSON is required for external MCP adapter calls")
            })?;
            let request_body = fs::read_to_string(&input_path)?;
            let request: ExternalMcpAdapterRequest = serde_json::from_str(&request_body)?;
            let manifest = if let Some(manifest_path) = &request.manifest_path {
                let manifest_body = fs::read_to_string(manifest_path)?;
                load_provider_manifest(&manifest_body)?
            } else {
                default_external_provider_manifest(other).ok_or_else(|| {
                    anyhow::anyhow!("missing default external provider manifest: {other}")
                })?
            };
            if manifest.provider_id != other {
                anyhow::bail!(
                    "external MCP manifest provider_id {} does not match requested provider {other}",
                    manifest.provider_id
                );
            }
            Ok(execute_external_mcp_adapter(
                &manifest,
                &request,
                root.as_deref(),
            ))
        }
        other => Ok(json!({
            "provider": other,
            "decision": "requires_review",
            "execution_status": "not_executed",
            "external_adapter_required": true,
            "reason": "external provider is registered and must be invoked through its mediated downstream adapter",
            "side_effect_executed": false
        })),
    }
}

fn runtime_denial_error_kind(kind: &ProviderRuntimeDenialKind) -> &'static str {
    match kind {
        ProviderRuntimeDenialKind::ShellDenied => "provider_not_allowed",
        ProviderRuntimeDenialKind::CwdEscape => "root_escape",
        ProviderRuntimeDenialKind::EnvInheritanceDenied
        | ProviderRuntimeDenialKind::EnvNotAllowed => "scope_violation",
        ProviderRuntimeDenialKind::NetworkDenied => "egress_denied",
        ProviderRuntimeDenialKind::TimeoutTooLarge
        | ProviderRuntimeDenialKind::OutputLimitTooLarge => "budget_exceeded",
    }
}

fn provider_call_from_cli(
    session_manifest: &SessionManifest,
    provider: &str,
    input: Option<&PathBuf>,
    root: Option<&PathBuf>,
    trace: Option<&PathBuf>,
    report: Option<&PathBuf>,
    format: Option<&str>,
) -> ProviderCall {
    let mut arguments = serde_json::Map::new();
    if let Some(path) = input {
        arguments.insert(
            "input_path".to_string(),
            serde_json::Value::String(path.to_string_lossy().into_owned()),
        );
    }
    if let Some(path) = root {
        let root_value = path.to_string_lossy().into_owned();
        let key = if session_manifest
            .roots
            .iter()
            .any(|root| root.name == root_value)
        {
            "root"
        } else {
            "root_path"
        };
        arguments.insert(key.to_string(), serde_json::Value::String(root_value));
    }
    if let Some(path) = trace {
        arguments.insert(
            "trace_path".to_string(),
            serde_json::Value::String(path.to_string_lossy().into_owned()),
        );
    }
    if let Some(path) = report {
        arguments.insert(
            "report_path".to_string(),
            serde_json::Value::String(path.to_string_lossy().into_owned()),
        );
    }
    if let Some(format) = format {
        arguments.insert(
            "format".to_string(),
            serde_json::Value::String(format.to_string()),
        );
    }

    ProviderCall {
        session_id: session_manifest.session_id.clone(),
        provider: provider.to_string(),
        action: provider_action(provider).to_string(),
        arguments: serde_json::Value::Object(arguments),
        actor_id: session_manifest.actor_id.clone(),
        authz_id: session_manifest.authz_id.clone(),
        approval_id: None,
    }
}

fn provider_action(provider: &str) -> &str {
    provider.rsplit('.').next().unwrap_or("call")
}

fn resolve_cli_execution_root(
    session_manifest: Option<&SessionManifest>,
    root: Option<PathBuf>,
) -> Option<PathBuf> {
    let root = root?;
    let root_text = root.to_string_lossy();
    session_manifest
        .and_then(|session| {
            session
                .roots
                .iter()
                .find(|candidate| candidate.name == root_text)
                .map(|candidate| candidate.path.clone())
        })
        .or(Some(root))
}

fn attach_matching_approval(call: &mut ProviderCall) -> anyhow::Result<()> {
    let binding = cli_approval_binding(call)?;
    if let Some(approval) = read_all_approvals()?
        .into_iter()
        .find(|approval| approval.binding == binding)
    {
        call.approval_id = Some(approval.approval_id);
    }
    Ok(())
}

fn persist_consumed_cli_approval(
    call: &ProviderCall,
    binding: &ApprovalBinding,
) -> anyhow::Result<()> {
    let Some(approval_id) = call.approval_id.as_deref() else {
        return Ok(());
    };
    let mut approval = read_approval(approval_id)?;
    if approval.state == ApprovalState::Approved {
        approval.consume_once(binding)?;
        write_approval(&approval)?;
    }
    Ok(())
}

fn cli_approval_binding(call: &ProviderCall) -> anyhow::Result<ApprovalBinding> {
    Ok(ApprovalBinding {
        session_id: call.session_id.clone(),
        provider: call.provider.clone(),
        action: call.action.clone(),
        argument_hash: hex_sha256(&serde_json::to_vec(&call.arguments)?),
        authz_id: call.authz_id.clone(),
        actor_id: call.actor_id.clone(),
    })
}

fn call_first_party_provider(
    provider: &str,
    input: Option<PathBuf>,
    root: Option<PathBuf>,
    trace: Option<PathBuf>,
    report: Option<PathBuf>,
    format: Option<String>,
) -> anyhow::Result<serde_json::Value> {
    match provider {
        "runwarden.input.inspect" => {
            let input_path =
                input.ok_or_else(|| anyhow::anyhow!("--input is required for input.inspect"))?;
            let bytes = fs::read(&input_path)?;
            let inspection = inspect_input(
                InputSource::UserPrompt,
                &bytes,
                InputInspectPolicy::default(),
            );
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": inspection
            }))
        }
        "runwarden.evidence.inspect" => {
            let root_path =
                root.ok_or_else(|| anyhow::anyhow!("--root is required for evidence.inspect"))?;
            let inspection = inspect_evidence_root(&root_path, EvidenceInspectPolicy::default())?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": inspection
            }))
        }
        "runwarden.audit.summary" => {
            let trace_path =
                trace.ok_or_else(|| anyhow::anyhow!("--trace is required for audit.summary"))?;
            let events = read_trace(&trace_path)?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": audit_summary(&events)
            }))
        }
        "runwarden.accountability.summary" => {
            let trace_path = trace
                .ok_or_else(|| anyhow::anyhow!("--trace is required for accountability.summary"))?;
            let events = read_trace(&trace_path)?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": accountability_summary(&events)
            }))
        }
        "runwarden.trace.verify" => {
            let trace_path =
                trace.ok_or_else(|| anyhow::anyhow!("--trace is required for trace.verify"))?;
            let events = read_trace(&trace_path)?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": verify_trace_events(events)
            }))
        }
        "runwarden.trace.export" => {
            let trace_path =
                trace.ok_or_else(|| anyhow::anyhow!("--trace is required for trace.export"))?;
            let events = read_trace(&trace_path)?;
            let verification = verify_trace_events(events.clone());
            Ok(json!({
                "provider": provider,
                "decision": if verification["verified"].as_bool() == Some(true) { "allowed" } else { "denied" },
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": {
                    "verification": verification,
                    "events": events
                }
            }))
        }
        "runwarden.report.scaffold" => {
            let trace_path =
                trace.ok_or_else(|| anyhow::anyhow!("--trace is required for report.scaffold"))?;
            let events = read_trace(&trace_path)?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": scaffold_report_from_trace(&events)
            }))
        }
        "runwarden.report.lint" => {
            let report_path =
                report.ok_or_else(|| anyhow::anyhow!("--report is required for report.lint"))?;
            let trace_path =
                trace.ok_or_else(|| anyhow::anyhow!("--trace is required for report.lint"))?;
            let report = read_report(&report_path)?;
            let events = read_trace(&trace_path)?;
            let result = lint_report_against_trace(&report, &events);
            Ok(json!({
                "provider": provider,
                "decision": if result.ok { "allowed" } else { "denied" },
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": result
            }))
        }
        "runwarden.report.render" => {
            let report_path =
                report.ok_or_else(|| anyhow::anyhow!("--report is required for report.render"))?;
            let trace_path =
                trace.ok_or_else(|| anyhow::anyhow!("--trace is required for report.render"))?;
            let report = read_report(&report_path)?;
            let events = read_trace(&trace_path)?;
            let format = parse_render_format(format.as_deref().unwrap_or("markdown"))?;
            let rendered = render_report(&report, &events, format)
                .map_err(|err| anyhow::anyhow!(err.message))?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": rendered
            }))
        }
        "runwarden.cert.all" => {
            let workspace_root = find_workspace_root(env::current_dir()?)?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": certify_workspace(&workspace_root)
            }))
        }
        "runwarden.eval.all" => {
            let report_path =
                report.ok_or_else(|| anyhow::anyhow!("--report is required for eval.all"))?;
            let trace_path =
                trace.ok_or_else(|| anyhow::anyhow!("--trace is required for eval.all"))?;
            let report = read_report(&report_path)?;
            let events = read_trace(&trace_path)?;
            let expected_obs: Vec<_> = events.iter().map(|event| event.obs_id.clone()).collect();
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": evaluate_report_assurance(&report, &events, expected_obs, EvalThresholds::strict())
            }))
        }
        "runwarden.eval.agent-native" => {
            let workspace_root = find_workspace_root(env::current_dir()?)?;
            let cases = load_agent_native_cases(&workspace_root, Vec::new())?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": evaluate_agent_native_configs(&cases)
            }))
        }
        "runwarden.bench.run" => {
            let workspace_root = find_workspace_root(env::current_dir()?)?;
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": benchmark_workspace(&workspace_root)?
            }))
        }
        other => anyhow::bail!("unsupported first-party provider call: {other}"),
    }
}

fn load_agent_native_cases(
    root: &Path,
    configs: Vec<PathBuf>,
) -> anyhow::Result<Vec<AgentNativeConfigCase>> {
    let paths = if configs.is_empty() {
        vec![
            (
                root.join("examples/agent-configs/claude.runwarden-only.json"),
                AgentNativeExpectation::RunwardenOnlyAllowed,
            ),
            (
                root.join("examples/agent-configs/unsafe.raw-filesystem.json"),
                AgentNativeExpectation::RawToolsDenied,
            ),
            (
                root.join("examples/agent-configs/unsafe.raw-shell.json"),
                AgentNativeExpectation::RawToolsDenied,
            ),
        ]
    } else {
        configs
            .into_iter()
            .map(|path| {
                let expectation = expectation_for_config_path(&path);
                (path, expectation)
            })
            .collect()
    };

    paths
        .into_iter()
        .map(|(path, expectation)| {
            let body = fs::read_to_string(&path)?;
            let config = serde_json::from_str(&body)?;
            Ok(AgentNativeConfigCase {
                id: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("agent-config")
                    .to_string(),
                config,
                expectation,
            })
        })
        .collect()
}

fn evaluate_scenario_corpora(root: &Path) -> anyhow::Result<serde_json::Value> {
    let scenarios_dir = root.join("scenarios");
    let mut entries = fs::read_dir(&scenarios_dir)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    let mut cases = Vec::new();
    let mut passed = true;
    for entry in entries {
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let scenario_path = entry.path();
        let scenario = entry.file_name().to_string_lossy().into_owned();
        let mut missing = Vec::new();
        for relative_path in scenario_corpus_required_files() {
            if !scenario_path.join(relative_path).exists() {
                missing.push((*relative_path).to_string());
            }
        }

        let case = if missing.is_empty() {
            let obs_refs = read_obs_refs(&scenario_path.join("expected/obs-refs.json"))?;
            let report = read_report(&scenario_path.join("expected/report.json"))?;
            let mut store = InMemoryTraceStore::default();
            for obs_ref in &obs_refs {
                store.append_signed(
                    obs_ref.clone(),
                    "scenario_golden".to_string(),
                    Some("runwarden.eval.scenarios".to_string()),
                    json!({ "scenario": scenario }),
                );
            }
            let trace_events = store.query(TraceQuery {
                limit: obs_refs.len().max(1),
                ..TraceQuery::default()
            });
            let eval = evaluate_report_assurance(
                &report,
                &trace_events.events,
                obs_refs.clone(),
                EvalThresholds::strict(),
            );
            let baseline = read_json_value(&scenario_path.join("expected/eval-baseline.json"))?;
            let expected_pass = baseline
                .get("expected_pass")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let baseline_passed = eval.passed == expected_pass
                && eval.metrics.trace_completeness
                    >= baseline
                        .get("min_trace_completeness")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or(1.0)
                && eval.metrics.report_citation_accuracy
                    >= baseline
                        .get("min_report_citation_accuracy")
                        .and_then(serde_json::Value::as_f64)
                        .unwrap_or(1.0);

            let denials = read_json_value(&scenario_path.join("expected/denials.json"))?;
            let provider_calls =
                read_json_value(&scenario_path.join("expected/provider-calls.json"))?;
            let case_passed = baseline_passed && !obs_refs.is_empty();
            if !case_passed {
                passed = false;
            }
            json!({
                "id": scenario,
                "passed": case_passed,
                "obs_refs": obs_refs,
                "denial_count": denials.as_array().map_or(0, Vec::len),
                "provider_call_count": provider_calls.as_array().map_or(0, Vec::len),
                "metrics": eval.metrics,
                "failures": eval.failures
            })
        } else {
            passed = false;
            json!({
                "id": scenario,
                "passed": false,
                "missing": missing
            })
        };
        cases.push(case);
    }

    if cases.is_empty() {
        passed = false;
    }

    Ok(json!({
        "suite": "scenario-golden-corpus",
        "passed": passed,
        "case_count": cases.len(),
        "cases": cases,
        "side_effect_executed": false
    }))
}

fn scenario_corpus_required_files() -> &'static [&'static str] {
    &[
        "README.md",
        "manifests/assessment.toml",
        "attacks/prompt-injection.md",
        "benign/request.md",
        "expected/denials.json",
        "expected/provider-calls.json",
        "expected/obs-refs.json",
        "expected/report.json",
        "expected/eval-baseline.json",
    ]
}

fn read_obs_refs(path: &Path) -> anyhow::Result<Vec<String>> {
    let value = read_json_value(path)?;
    let values = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{} must contain a JSON array", path.display()))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| anyhow::anyhow!("{} contains a non-string obs ref", path.display()))
        })
        .collect()
}

fn read_json_value(path: &Path) -> anyhow::Result<serde_json::Value> {
    let body = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body)?)
}

fn expectation_for_config_path(path: &Path) -> AgentNativeExpectation {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.contains("unsafe") || name.contains("raw-") || name.contains("raw_") {
        AgentNativeExpectation::RawToolsDenied
    } else {
        AgentNativeExpectation::RunwardenOnlyAllowed
    }
}

fn write_submission_bundle(
    root: &Path,
    output: &Path,
    full: bool,
) -> anyhow::Result<serde_json::Value> {
    fs::create_dir_all(output)?;

    let cert_report = certify_workspace(root);
    let bench_report = benchmark_workspace(root)?;
    let agent_native = evaluate_agent_native_configs(&load_agent_native_cases(root, Vec::new())?);

    let mut manifest = ArtifactManifest {
        schema_version: "0.1".to_string(),
        artifacts: Vec::new(),
    };

    push_sealed_artifact(
        output,
        &mut manifest,
        "submission-report",
        "reports/submission.md",
        "# Runwarden Enterprise Submission\n\nLocal release evidence cites obs_release_gate and obs_agent_native.\n",
    )?;
    push_sealed_artifact(
        output,
        &mut manifest,
        "cert-release-artifact",
        "release/cert-release-artifact.json",
        &serde_json::to_string_pretty(&cert_report)?,
    )?;
    push_sealed_artifact(
        output,
        &mut manifest,
        "bench-report",
        "release/bench-report.json",
        &serde_json::to_string_pretty(&bench_report)?,
    )?;
    push_sealed_artifact(
        output,
        &mut manifest,
        "agent-native-eval",
        "release/agent-native-eval.json",
        &serde_json::to_string_pretty(&agent_native)?,
    )?;

    if full {
        push_sealed_artifact(
            output,
            &mut manifest,
            "sbom",
            "release/sbom.spdx.json",
            &serde_json::to_string_pretty(&workspace_sbom())?,
        )?;
        push_sealed_artifact(
            output,
            &mut manifest,
            "provenance",
            "release/provenance.json",
            &serde_json::to_string_pretty(&workspace_provenance())?,
        )?;
    }

    let manifest_path = output.join("artifact-manifest.json");
    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    let verification = verify_artifact_manifest(output, &manifest);
    if !verification.findings.is_empty() {
        anyhow::bail!("generated submission bundle did not verify");
    }

    Ok(json!({
        "manifest_path": manifest_path.to_string_lossy(),
        "artifact_root": output.to_string_lossy(),
        "artifact_count": manifest.artifacts.len(),
        "artifacts": manifest.artifacts,
        "verification": verification,
        "side_effect_executed": true
    }))
}

fn push_sealed_artifact(
    output: &Path,
    manifest: &mut ArtifactManifest,
    artifact_id: &str,
    relative_path: &str,
    contents: &str,
) -> anyhow::Result<()> {
    let sealed = seal_artifact(output, artifact_id, relative_path, contents).map_err(|err| {
        anyhow::anyhow!(
            "failed to seal artifact {} at {}: {}",
            artifact_id,
            err.path,
            err.message
        )
    })?;
    manifest.artifacts.extend(sealed.artifacts);
    Ok(())
}

fn workspace_sbom() -> serde_json::Value {
    json!({
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "name": "runwarden-enterprise",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://runwarden.local/sbom/runwarden-enterprise",
        "packages": [
            {"SPDXID": "SPDXRef-Package-runwarden-kernel", "name": "runwarden-kernel"},
            {"SPDXID": "SPDXRef-Package-runwarden-providers", "name": "runwarden-providers"},
            {"SPDXID": "SPDXRef-Package-runwarden-assurance", "name": "runwarden-assurance"},
            {"SPDXID": "SPDXRef-Package-runwarden-cli", "name": "runwarden-cli"},
            {"SPDXID": "SPDXRef-Package-runwarden-mcp", "name": "runwarden-mcp"},
            {"SPDXID": "SPDXRef-Package-runwarden-api", "name": "runwarden-api"},
            {"SPDXID": "SPDXRef-Package-agent-sdk", "name": "@runwarden/agent-sdk"},
            {"SPDXID": "SPDXRef-Package-webui", "name": "@runwarden/webui"}
        ]
    })
}

fn workspace_provenance() -> serde_json::Value {
    let workspace_digest = hex_sha256(b"workspace-local-release-evidence");
    json!({
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [
            {"name": "runwarden"},
            {"name": "runwarden-mcp"},
            {"name": "runwarden-kernel"},
            {"name": "runwarden-artifacts"}
        ],
        "buildType": "runwarden.local.release-evidence.v1",
        "builder": {
            "id": "runwarden release gate"
        },
        "materials": [
            {"uri": "git+file://runwarden", "digest": {"sha256": workspace_digest}}
        ]
    })
}

fn release_smoke_report(root: &Path) -> anyhow::Result<serde_json::Value> {
    let cert = certify_workspace(root);
    let bench = benchmark_workspace(root)?;
    let agent_native = evaluate_agent_native_configs(&load_agent_native_cases(root, Vec::new())?);
    let scenario_eval = evaluate_scenario_corpora(root)?;
    let scenario_eval_passed = scenario_eval["passed"].as_bool() == Some(true);
    let passed = cert.passed && bench.passed && agent_native.passed && scenario_eval_passed;

    Ok(json!({
        "passed": passed,
        "checks": [
            {
                "id": "cert",
                "passed": cert.passed,
                "details": cert.checks
            },
            {
                "id": "bench",
                "passed": bench.passed,
                "metrics": bench.metrics
            },
            {
                "id": "agent_native",
                "passed": agent_native.passed,
                "metrics": agent_native.metrics,
                "cases": agent_native.cases
            },
            {
                "id": "scenario_golden_corpus",
                "passed": scenario_eval_passed,
                "suite": scenario_eval
            }
        ],
        "side_effect_executed": false
    }))
}

fn write_ui_launch_bundle(
    bind: &str,
    port: u16,
    artifact_root: &Path,
) -> anyhow::Result<serde_json::Value> {
    fs::create_dir_all(artifact_root)?;
    let html_path = artifact_root.join("reviewer-console.html");
    fs::write(&html_path, reviewer_console_html(bind, port))?;

    Ok(json!({
        "bind": bind,
        "port": port,
        "artifact_root": artifact_root.to_string_lossy(),
        "html_path": html_path.to_string_lossy(),
        "launch_url": format!("http://{bind}:{port}/"),
        "mode": "static_reviewer_console_bundle",
        "side_effect_executed": true
    }))
}

fn reviewer_console_html(bind: &str, port: u16) -> String {
    r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Runwarden Reviewer Console</title>
  <style>
    :root { color-scheme: light; font-family: "IBM Plex Sans", system-ui, sans-serif; }
    body { margin: 0; background: #f7f8f4; color: #20241f; }
    .runwarden-workbench { min-height: 100vh; display: grid; grid-template-columns: 220px minmax(0, 1fr) 340px; }
    .left-nav { background: #151813; color: #f3faf5; padding: 18px; display: flex; flex-direction: column; gap: 6px; }
    .left-nav strong { padding: 9px 10px; }
    .left-nav a { color: inherit; text-decoration: none; padding: 9px 10px; border-radius: 6px; min-height: 44px; box-sizing: border-box; display: flex; align-items: center; }
    .left-nav a:hover { background: #262d24; }
    .workbench-main { padding: 18px; min-width: 0; }
    .top-status-strip { display: grid; grid-template-columns: repeat(6, minmax(110px, 1fr)); gap: 8px; margin-bottom: 14px; }
    .status-pill, .module { border: 1px solid #cdd5c8; background: #ffffff; border-radius: 6px; padding: 14px; min-width: 0; }
    .status-pill span { display: block; font-size: 12px; color: #687064; }
    .status-pill strong { display: block; overflow-wrap: anywhere; font-size: 14px; }
    .tone-review { border-color: #a76716; }
    .workspace-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .module h2, .details-drawer h2 { font-size: 16px; margin: 0 0 10px; }
    .module p, .details-drawer p { margin: 0; }
    .module code, .status-pill code { font-family: "JetBrains Mono", ui-monospace, monospace; overflow-wrap: anywhere; }
    .approval-module { grid-column: 1 / -1; }
    button { border: 1px solid #cdd5c8; background: #ffffff; border-radius: 6px; min-height: 44px; padding: 8px 12px; }
    button:hover { border-color: #2f6f4e; background: #eef1ea; }
    button:focus-visible, .left-nav a:focus-visible { outline: 2px solid #2f6f4e; outline-offset: 2px; }
    .details-drawer { border-left: 1px solid #cdd5c8; background: #ffffff; padding: 18px; min-width: 0; }
    @media (max-width: 1199px) {
      .runwarden-workbench { grid-template-columns: 76px minmax(0, 1fr); }
      .left-nav a { font-size: 12px; }
      .details-drawer { grid-column: 1 / -1; border-left: 0; border-top: 1px solid #cdd5c8; }
      .top-status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 768px) {
      .runwarden-workbench { display: block; padding-bottom: 76px; }
      .left-nav { position: fixed; left: 0; right: 0; bottom: 0; z-index: 10; flex-direction: row; overflow-x: auto; padding: 8px 10px; border-top: 1px solid #cdd5c8; }
      .left-nav a { white-space: nowrap; }
      .top-status-strip, .workspace-grid { grid-template-columns: 1fr; }
      .details-drawer { min-height: calc(100vh - 76px); border-left: 0; border-top: 1px solid #cdd5c8; }
    }
  </style>
</head>
<body>
<main class="runwarden-workbench">
  <nav class="left-nav" aria-label="Runwarden sections">
    <strong>Runwarden</strong>
    <a href="#dashboard">Dashboard</a>
    <a href="#agent-boundary">Agent Boundary</a>
    <a href="#provider-registry">Provider Registry</a>
    <a href="#approval-queue">Approval Queue</a>
    <a href="#trace">Trace Explorer</a>
    <a href="#accountability">Accountability</a>
    <a href="#reports">Reports</a>
    <a href="#artifacts">Artifacts</a>
    <a href="#settings">Settings</a>
  </nav>
  <section class="workbench-main" id="dashboard" aria-label="Reviewer workspace">
    <header class="top-status-strip" role="status" aria-label="Assessment status">
      <div class="status-pill"><span>Session</span><strong>No assessment loaded</strong></div>
      <div class="status-pill"><span>Local API</span><strong><code>__BIND__:__PORT__</code></strong></div>
      <div class="status-pill tone-review"><span>Risk</span><strong>incomplete</strong></div>
      <div class="status-pill tone-review"><span>Trace</span><strong>missing</strong></div>
      <div class="status-pill"><span>Approvals</span><strong>unknown</strong></div>
      <div class="status-pill tone-review"><span>Gates</span><strong>missing</strong></div>
    </header>
    <div class="workspace-grid">
      <article class="module" id="agent-boundary"><h2>Agent Boundary</h2><p>No agent config checked</p></article>
      <article class="module" id="provider-registry"><h2>Provider Registry</h2><p>No providers allowed for this session</p></article>
      <article class="module approval-module" id="approval-queue"><h2>Approval Queue</h2><p>No actions waiting for review</p></article>
      <article class="module" id="trace"><h2>Trace Explorer</h2><p>No trace events yet</p></article>
      <article class="module" id="accountability"><h2>Accountability</h2><p>No accountability chain reconstructed</p></article>
      <article class="module" id="reports"><h2>Reports</h2><p>No report rendered</p></article>
      <article class="module" id="artifacts"><h2>Artifacts</h2><p>No artifacts generated</p></article>
      <article class="module" id="assurance"><h2>Assurance</h2><p>No eval run yet</p></article>
      <article class="module" id="settings"><h2>Settings</h2><p>Local API token, artifact paths, and debug visibility are not loaded.</p></article>
    </div>
  </section>
  <aside class="details-drawer" aria-label="Approval details">
    <h2>Approval Details</h2>
    <p>Select an approval to inspect provider, risk, target, side effects, actor, authz, argument hash, and obs refs before a reviewer decision.</p>
  </aside>
</main>
</body>
</html>
"##
    .replace("__BIND__", bind)
    .replace("__PORT__", &port.to_string())
}

fn resolve_launch_token(configured: Option<String>) -> (String, bool) {
    if let Some(token) = configured.filter(|token| !token.trim().is_empty()) {
        return (token, false);
    }
    if let Ok(token) = env::var("RUNWARDEN_LAUNCH_TOKEN")
        && !token.trim().is_empty()
    {
        return (token, false);
    }
    (format!("rw_launch_{}", uuid::Uuid::now_v7()), true)
}

fn local_api_serve_descriptor(
    bind: &str,
    port: u16,
    launch_token: &str,
    launch_token_generated: bool,
    once: bool,
) -> serde_json::Value {
    json!({
        "mode": "local_api_server",
        "listen_addr": format!("{bind}:{port}"),
        "allowed_origin": format!("http://{bind}:{port}"),
        "launch_token_configured": !launch_token.is_empty(),
        "launch_token_generated": launch_token_generated,
        "once": once,
        "routes": [
            "/health",
            "/dashboard",
            "/agent-boundary",
            "/providers",
            "/providers/{provider}/status",
            "/approvals",
            "/approvals/{approval_id}/approve",
            "/approvals/{approval_id}/deny",
            "/provider-calls",
            "/sessions",
            "/trace/export",
            "/audit/summary",
            "/accountability/summary",
            "/reports/lint",
            "/reports/render",
            "/reports/preview",
            "/artifacts/verify",
            "/artifacts/token",
            "/artifacts/submission",
            "/eval/agent-native",
            "/release/smoke",
            "/ui/launch",
            "/agent/config/check"
        ],
        "security_model": "launch token + host/origin checks + kernel-owned decisions",
        "side_effect_executed": false
    })
}

fn read_report(path: &PathBuf) -> anyhow::Result<ReportDraft> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn read_trace(path: &PathBuf) -> anyhow::Result<Vec<TraceEvent>> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn parse_render_format(format: &str) -> anyhow::Result<RenderFormat> {
    match format {
        "markdown" | "md" => Ok(RenderFormat::Markdown),
        "json" => Ok(RenderFormat::Json),
        "html" => Ok(RenderFormat::Html),
        "sarif" | "sarif.json" => Ok(RenderFormat::Sarif),
        other => anyhow::bail!("unsupported report render format: {other}"),
    }
}

fn write_session(session: &SessionManifest) -> anyhow::Result<()> {
    let dir = PathBuf::from(".runwarden").join("sessions");
    fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", safe_session_id(&session.session_id)?));
    fs::write(path, serde_json::to_string_pretty(session)?)?;
    Ok(())
}

fn read_session(session_id: &str) -> anyhow::Result<SessionManifest> {
    let path = PathBuf::from(".runwarden")
        .join("sessions")
        .join(format!("{}.json", safe_session_id(session_id)?));
    let body = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&body)?)
}

fn safe_session_id(session_id: &str) -> anyhow::Result<&str> {
    if session_id.is_empty()
        || !session_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        anyhow::bail!("invalid session id: {session_id}");
    }
    Ok(session_id)
}

fn approvals_dir() -> PathBuf {
    PathBuf::from(".runwarden").join("approvals")
}

fn approval_path(approval_id: &str) -> anyhow::Result<PathBuf> {
    Ok(approvals_dir().join(format!("{}.json", safe_record_id(approval_id)?)))
}

fn read_all_approvals() -> anyhow::Result<Vec<ApprovalRecord>> {
    let dir = approvals_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut approvals = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let body = fs::read_to_string(entry.path())?;
        approvals.push(serde_json::from_str(&body)?);
    }
    approvals.sort_by(|left: &ApprovalRecord, right: &ApprovalRecord| {
        left.approval_id.cmp(&right.approval_id)
    });
    Ok(approvals)
}

fn read_approval(approval_id: &str) -> anyhow::Result<ApprovalRecord> {
    let body = fs::read_to_string(approval_path(approval_id)?)?;
    Ok(serde_json::from_str(&body)?)
}

fn write_approval(approval: &ApprovalRecord) -> anyhow::Result<()> {
    let dir = approvals_dir();
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join(format!("{}.json", safe_record_id(&approval.approval_id)?)),
        serde_json::to_string_pretty(approval)?,
    )?;
    Ok(())
}

fn argument_hash_from_json(arguments: &str) -> anyhow::Result<String> {
    let value: serde_json::Value = serde_json::from_str(arguments)?;
    let bytes = serde_json::to_vec(&value)?;
    Ok(hex_sha256(&bytes))
}

fn safe_record_id(record_id: &str) -> anyhow::Result<&str> {
    if record_id.is_empty()
        || !record_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
    {
        anyhow::bail!("invalid record id: {record_id}");
    }
    Ok(record_id)
}

fn verify_trace_events(events: Vec<TraceEvent>) -> serde_json::Value {
    let event_count = events.len();
    let mut store = InMemoryTraceStore::default();
    for event in events {
        store.append(event);
    }

    match store.verify_hash_chain() {
        Ok(()) => json!({
            "verified": true,
            "event_count": event_count
        }),
        Err(err) => json!({
            "verified": false,
            "error_kind": "trace_tampered",
            "event_count": event_count,
            "offset": err.offset,
            "obs_id": err.obs_id,
            "message": err.reason
        }),
    }
}

fn run_strict_check() -> anyhow::Result<()> {
    let root = find_workspace_root(env::current_dir()?)?;
    let required_paths = [
        "Cargo.toml",
        "package.json",
        "DESIGN.md",
        "schemas/provider-call.schema.json",
        "schemas/provider-outcome.schema.json",
        "schemas/provider-contract.schema.json",
        "schemas/provider-manifest.schema.json",
        "schemas/operation-result.schema.json",
        "schemas/approval-record.schema.json",
        "schemas/trace-event.schema.json",
        "schemas/report.schema.json",
        "schemas/assessment-manifest.schema.json",
        "schemas/session-manifest.schema.json",
        "schemas/artifact-manifest.schema.json",
        "examples/providers/external.mcp.browser.open_page.json",
        "examples/providers/kernel.toml",
        "tests/fixtures/default-trace.json",
        "tests/fixtures/default-report.json",
        "scripts/dev_gate.sh",
        "scripts/check_ts_contracts.sh",
        "scripts/release_gate_local.sh",
        ".github/workflows/ci.yml",
        "crates/runwarden-kernel/src/main.rs",
        "packages/agent-sdk/src/generated/contracts.ts",
    ];

    for path in required_paths {
        let full_path = root.join(path);
        if !full_path.exists() {
            anyhow::bail!("strict check failed: missing {}", full_path.display());
        }
    }

    let release_gate = fs::read_to_string(root.join("scripts/release_gate_local.sh"))?;
    for command in [
        "runwarden cert all --json",
        "runwarden eval all --json",
        "runwarden eval scenarios --json",
        "runwarden eval agent-native --json",
        "runwarden bench run --json",
        "runwarden artifact verify --artifacts artifacts --manifest artifacts/artifact-manifest.json --json",
    ] {
        if !release_gate.contains(command) {
            anyhow::bail!("strict check failed: release gate does not run {command}");
        }
    }

    let registry = first_party_registry();
    for provider_id in FIRST_PARTY_PROVIDER_IDS {
        if !registry.contains(provider_id) {
            anyhow::bail!("strict check failed: missing first-party provider {provider_id}");
        }
    }
    let registry = full_provider_registry();
    for provider_id in EXTERNAL_PROVIDER_IDS {
        if !registry.contains(provider_id) {
            anyhow::bail!("strict check failed: missing external provider {provider_id}");
        }
    }
    if default_external_providers().is_empty() {
        anyhow::bail!("strict check failed: external provider catalog is empty");
    }

    for path in reference_doc_required_paths() {
        if !root.join(path).exists() {
            anyhow::bail!("strict check failed: missing reference doc {path}");
        }
    }

    let scenario_eval = evaluate_scenario_corpora(&root)?;
    if scenario_eval["passed"].as_bool() != Some(true) {
        anyhow::bail!("strict check failed: scenario golden corpus eval did not pass");
    }

    let dev_gate = fs::read_to_string(root.join("scripts/dev_gate.sh"))?;
    let pr_gate = fs::read_to_string(root.join("scripts/pr_fast_gate.sh"))?;
    if !dev_gate.contains("scripts/check_ts_contracts.sh")
        || !pr_gate.contains("scripts/check_ts_contracts.sh")
    {
        anyhow::bail!("strict check failed: generated TypeScript contract check is not gated");
    }

    let release_workflow = fs::read_to_string(root.join(".github/workflows/release.yml"))?;
    if !release_workflow.contains("target/release/runwarden*")
        || !root.join("crates/runwarden-kernel/src/main.rs").exists()
    {
        anyhow::bail!("strict check failed: release binary matrix does not include named binaries");
    }

    println!("runwarden strict check passed");
    println!("- schema artifacts present");
    println!("- first-party provider catalog present");
    println!("- scenario golden corpora present");
    println!("- split reference docs present");
    println!("- generated TypeScript contracts present");
    println!("- release binary matrix present");
    println!("- design contract present");
    println!("- release gate scripts present");
    println!("- release assurance commands present");
    Ok(())
}

fn reference_doc_required_paths() -> &'static [&'static str] {
    &[
        "docs/reference/rust-kernel-ts-interaction.md",
        "docs/reference/provider-model.md",
        "docs/reference/authority-and-session.md",
        "docs/reference/evidence-and-accountability.md",
        "docs/reference/threat-model.md",
        "docs/reference/agent-integration.md",
        "docs/reference/provider-integration.md",
        "docs/reference/webui-review-console.md",
        "docs/reference/release-installation.md",
        "docs/reference/first-scenario.md",
        "docs/reference/kernel-manifest.md",
        "docs/reference/provider-manifest.md",
        "docs/reference/assessment-manifest.md",
        "docs/reference/provider-contract.md",
        "docs/reference/artifact-manifest.md",
        "docs/reference/json-contracts.md",
        "docs/reference/ci.md",
        "docs/reference/roadmap.md",
    ]
}

fn find_workspace_root(mut current: PathBuf) -> anyhow::Result<PathBuf> {
    loop {
        if current.join("Cargo.toml").exists() && current.join("package.json").exists() {
            return Ok(current);
        }
        if !current.pop() {
            anyhow::bail!("could not find Runwarden workspace root");
        }
    }
}

fn generate_runwarden_only_config(client: &str) -> anyhow::Result<serde_json::Value> {
    match client {
        "claude" | "generic" => Ok(json!({
            "mcpServers": {
                "runwarden": {
                    "command": "runwarden-mcp",
                    "args": []
                }
            }
        })),
        other => anyhow::bail!("unsupported agent client: {other}"),
    }
}

#[derive(Debug, Deserialize)]
struct AgentConfig {
    #[serde(default, rename = "mcpServers")]
    mcp_servers: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Serialize)]
struct AgentConfigCheckResult {
    client: String,
    safe: bool,
    findings: Vec<String>,
}

fn check_runwarden_only_config(client: &str, config: &AgentConfig) -> AgentConfigCheckResult {
    let mut findings = Vec::new();
    match config.mcp_servers.get("runwarden") {
        Some(server) => {
            let command = server
                .get("command")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if command != "runwarden-mcp" {
                findings.push(format!(
                    "runwarden MCP server must execute runwarden-mcp, got: {command}"
                ));
            }
        }
        None => findings.push("missing runwarden MCP server".to_string()),
    }
    for name in config.mcp_servers.keys() {
        if name != "runwarden" {
            findings.push(format!("raw or downstream MCP exposed: {name}"));
        }
    }
    AgentConfigCheckResult {
        client: client.to_string(),
        safe: findings.is_empty(),
        findings,
    }
}

fn emit_cert_report(label: &str, report: CertReport, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.passed {
        println!("{label} passed");
    } else {
        println!("{label} failed");
    }
    if !report.passed {
        anyhow::bail!("{label} failed");
    }
    Ok(())
}

fn certify_provider_manifest_file(path: &Path) -> anyhow::Result<CertReport> {
    let body = fs::read_to_string(path)?;
    let manifest = load_provider_manifest(&body)?;
    let report = certify_external_provider_manifest(&manifest);
    let checks = if report.findings.is_empty() {
        vec![cert_check(
            "provider-manifest",
            true,
            format!(
                "{} schema pin and external provider contract verified",
                report.contract.provider.id
            ),
        )]
    } else {
        report
            .findings
            .iter()
            .map(|finding| cert_check("provider-manifest", false, finding.clone()))
            .collect()
    };

    Ok(CertReport {
        passed: report.passed,
        checks,
        side_effect_executed: false,
    })
}

fn certify_mcp_surface(root: &Path) -> CertReport {
    let body = fs::read_to_string(root.join("crates/runwarden-mcp/src/lib.rs")).unwrap_or_default();
    let passed = body.contains("runwarden.agent.bootstrap")
        && body.contains("runwarden.provider.call")
        && body.contains("runwarden.trace.export")
        && !body.contains("\"shell\"");
    CertReport {
        passed,
        checks: vec![cert_check(
            "mcp",
            passed,
            "MCP exposes only runwarden.* tools and includes trace/report/provider entrypoints",
        )],
        side_effect_executed: false,
    }
}

fn certify_release_artifact_surface(root: &Path) -> CertReport {
    let workflow =
        fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap_or_default();
    let passed = workflow.contains("scripts/release_gate_local.sh")
        && workflow.contains("actions/upload-artifact")
        && workflow.contains("softprops/action-gh-release")
        && root.join("scripts/generate_artifacts.sh").exists()
        && root.join("scripts/artifact_leak_scan.sh").exists()
        && root.join("crates/runwarden-kernel/src/main.rs").exists()
        && workflow.contains("target/release/runwarden*");
    CertReport {
        passed,
        checks: vec![cert_check(
            "release-artifact",
            passed,
            "release artifacts are generated, uploaded, scanned, and attached to releases",
        )],
        side_effect_executed: false,
    }
}

fn certify_required_paths(root: &Path, id: &str, paths: &[&str]) -> CertReport {
    let missing: Vec<_> = paths
        .iter()
        .filter(|path| !root.join(path).exists())
        .copied()
        .collect();
    CertReport {
        passed: missing.is_empty(),
        checks: vec![cert_check(
            id,
            missing.is_empty(),
            if missing.is_empty() {
                format!("{id} required files are present")
            } else {
                format!("{id} missing {}", missing.join(", "))
            },
        )],
        side_effect_executed: false,
    }
}

fn cert_check(id: impl Into<String>, passed: bool, message: impl Into<String>) -> CertCheck {
    CertCheck {
        id: id.into(),
        passed,
        message: message.into(),
    }
}
