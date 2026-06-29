use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use runwarden_assurance::eval::{EvalThresholds, evaluate_report_assurance};
use runwarden_assurance::report::{
    RenderFormat, ReportDraft, lint_report_against_trace, render_report,
};
use runwarden_kernel::authority::{ApprovalBinding, ApprovalRecord, ApprovalState};
use runwarden_kernel::contracts::{PolicyDecision, ProviderCall, ProviderClass, ProviderOutcome};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery, hex_sha256};
use runwarden_kernel::kernel::{KernelEnforcer, KernelPolicy, ScopedRoot};
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_providers::catalog::{
    EXTERNAL_PROVIDER_IDS, FIRST_PARTY_PROVIDER_IDS, full_provider_registry,
};
use runwarden_providers::input::{InputInspectPolicy, InputSource, inspect_input};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use time::OffsetDateTime;

const CONTEST_SCENARIOS: &[&str] = &[
    "prompt-injection-file-exfil",
    "tool-hijack-email-api",
    "memory-knowledge-poisoning",
    "environment-local-web-risk",
];

#[derive(Debug, Parser)]
#[command(name = "runwarden")]
#[command(about = "Contest red-team range for Runwarden-mediated agent tools")]
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
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Eval {
        #[command(subcommand)]
        command: EvalCommand,
    },
    Demo {
        #[command(subcommand)]
        command: DemoCommand,
    },
    Ui {
        #[command(subcommand)]
        command: UiCommand,
    },
    Approval {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    Authority {
        #[command(subcommand)]
        command: AuthorityCommand,
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
enum ReportCommand {
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
        report: Option<PathBuf>,
        #[arg(long)]
        trace: Option<PathBuf>,
        #[arg(long = "scenario-suite")]
        scenario_suite: Option<PathBuf>,
        #[arg(long, default_value = "markdown")]
        format: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EvalCommand {
    Scenarios {
        #[arg(long, default_value = "scenarios")]
        suite: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DemoCommand {
    Run {
        #[arg(long)]
        scenario: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum UiCommand {
    Build {
        #[arg(long, default_value = "artifacts/demo")]
        input: PathBuf,
        #[arg(long, default_value = "artifacts/reviewer-console.html")]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Serve {
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 8088)]
        port: u16,
        #[arg(long, default_value = "artifacts/reviewer-console.html")]
        file: PathBuf,
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
        Command::Init => println!("runwarden initialized"),
        Command::Check { strict } => {
            if strict {
                run_strict_check()?;
            } else {
                println!("runwarden check passed");
            }
        }
        Command::Session { command } => run_session_command(command)?,
        Command::Provider { command } => run_provider_command(command)?,
        Command::Trace { command } => run_trace_command(command)?,
        Command::Report { command } => run_report_command(command)?,
        Command::Eval { command } => run_eval_command(command)?,
        Command::Demo { command } => run_demo_command(command)?,
        Command::Ui { command } => run_ui_command(command)?,
        Command::Approval { command } => run_approval_command(command)?,
        Command::Authority { command } => run_authority_command(command)?,
    }
    Ok(())
}

fn run_session_command(command: SessionCommand) -> anyhow::Result<()> {
    match command {
        SessionCommand::Create {
            manifest,
            session,
            json,
        } => {
            let manifest_body = fs::read_to_string(&manifest)?;
            let assessment = AssessmentManifest::from_toml_str(&manifest_body)?;
            let assessment = assessment_with_manifest_relative_roots(&manifest, assessment)?;
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
    }
    Ok(())
}

fn run_provider_command(command: ProviderCommand) -> anyhow::Result<()> {
    match command {
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
            let mut execution_input = input.clone();
            let mut execution_trace = trace.clone();
            let mut execution_report = report.clone();
            let mut call = provider_call_from_cli(CliProviderCallInput {
                session_id: session_manifest
                    .as_ref()
                    .map(|session| session.session_id.as_str())
                    .unwrap_or("cli-provider-call"),
                actor_id: session_manifest
                    .as_ref()
                    .and_then(|session| session.actor_id.clone()),
                authz_id: session_manifest
                    .as_ref()
                    .and_then(|session| session.authz_id.clone()),
                session_manifest: session_manifest.as_ref(),
                provider: &provider,
                input: input.as_ref(),
                root: root.as_ref(),
                trace: trace.as_ref(),
                report: report.as_ref(),
                format: format.as_deref(),
            });

            if let Some(session_manifest) = session_manifest.as_ref() {
                let resolved_paths =
                    resolve_session_provider_argument_paths(session_manifest, &mut call)?;
                if let Some(path) = resolved_paths.input {
                    execution_input = Some(path);
                }
                if let Some(path) = resolved_paths.trace {
                    execution_trace = Some(path);
                }
                if let Some(path) = resolved_paths.report {
                    execution_report = Some(path);
                }
            }

            let mut pre_read_enforcer = KernelEnforcer::new(
                full_provider_registry(),
                cli_provider_policy(
                    session_manifest.as_ref(),
                    &provider,
                    input.as_ref(),
                    root.as_ref(),
                    trace.as_ref(),
                    report.as_ref(),
                ),
            );
            let pre_read_outcome = pre_read_enforcer.evaluate_call(&call);
            if pre_read_outcome.decision == PolicyDecision::Denied {
                emit_provider_policy_outcome(&pre_read_outcome, json)?;
                return Ok(());
            }

            bind_cli_file_digests(&mut call)?;
            attach_matching_approval(&mut call)?;
            let mut enforcer = KernelEnforcer::new(
                full_provider_registry(),
                cli_provider_policy(
                    session_manifest.as_ref(),
                    &provider,
                    input.as_ref(),
                    root.as_ref(),
                    trace.as_ref(),
                    report.as_ref(),
                ),
            );
            for approval in read_all_approvals()? {
                enforcer.add_approval(approval);
            }
            let outcome = enforcer.evaluate_call(&call);
            if outcome.decision != PolicyDecision::Allowed {
                emit_provider_policy_outcome(&outcome, json)?;
                return Ok(());
            }
            verify_cli_file_digests(&call)?;
            if call
                .approval_id
                .as_deref()
                .and_then(|approval_id| enforcer.approval_state(approval_id))
                == Some(ApprovalState::Consumed)
            {
                persist_consumed_cli_approval(&call, &enforcer.approval_binding_for_call(&call))?;
            }

            let result = if provider_is_external(&provider) {
                call_external_provider(&provider)
            } else {
                call_first_party_provider(
                    &provider,
                    execution_input,
                    execution_trace,
                    execution_report,
                    format,
                )?
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("provider call completed: {provider}");
            }
        }
    }
    Ok(())
}

fn run_trace_command(command: TraceCommand) -> anyhow::Result<()> {
    match command {
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
            for event in events {
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
            let refs = if compact_refs {
                json!(
                    page.events
                        .iter()
                        .map(|event| event.obs_id.clone())
                        .collect::<Vec<_>>()
                )
            } else {
                Value::Null
            };
            let event_count = page.events.len();
            let export = json!({
                "verified": true,
                "event_count": event_count,
                "events": page.events,
                "page": page,
                "compact_refs": refs,
                "side_effect_executed": false
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&export)?);
            } else {
                println!("exported {event_count} trace events");
            }
        }
    }
    Ok(())
}

fn run_report_command(command: ReportCommand) -> anyhow::Result<()> {
    match command {
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
            scenario_suite,
            format,
            output,
            json,
        } => {
            let root = find_workspace_root(env::current_dir()?)?;
            let format = parse_render_format(&format)?;
            let rendered = if let Some(suite) = scenario_suite {
                render_scenario_suite_report(&root, &suite, format)?
            } else {
                let report = report.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--report is required without --scenario-suite")
                })?;
                let trace = trace.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--trace is required without --scenario-suite")
                })?;
                let report = read_report(report)?;
                let trace = read_trace(trace)?;
                render_report(&report, &trace, format)
                    .map_err(|err| anyhow::anyhow!(err.message))?
            };

            if let Some(output) = output {
                let output_path = resolve_workspace_output_path(&root, &output, "report output")?;
                if let Some(parent) = output_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&output_path, rendered.contents.as_bytes())?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "path": output_path.to_string_lossy(),
                            "extension": rendered.extension,
                            "side_effect_executed": true
                        }))?
                    );
                } else {
                    println!("wrote report {}", output_path.display());
                }
            } else if json {
                println!("{}", serde_json::to_string_pretty(&rendered)?);
            } else {
                println!("{}", rendered.contents);
            }
        }
    }
    Ok(())
}

fn run_eval_command(command: EvalCommand) -> anyhow::Result<()> {
    match command {
        EvalCommand::Scenarios { suite, json } => {
            let root = find_workspace_root(env::current_dir()?)?;
            let result = evaluate_scenario_corpora(&root, &suite)?;
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
    }
    Ok(())
}

fn run_demo_command(command: DemoCommand) -> anyhow::Result<()> {
    match command {
        DemoCommand::Run {
            scenario,
            output,
            json,
        } => {
            let root = find_workspace_root(env::current_dir()?)?;
            let result = run_demo_scenario(&root, &scenario, &output)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "wrote demo scenario {} to {}",
                    scenario,
                    result["output_dir"].as_str().unwrap_or("<unknown>")
                );
            }
        }
    }
    Ok(())
}

fn run_ui_command(command: UiCommand) -> anyhow::Result<()> {
    match command {
        UiCommand::Build {
            input,
            output,
            json,
        } => {
            let root = find_workspace_root(env::current_dir()?)?;
            let input_path = resolve_workspace_output_path(&root, &input, "ui input")?;
            let output_path = resolve_workspace_output_path(&root, &output, "ui output")?;
            let html = render_static_demo_console(&input_path)?;
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&output_path, html.as_bytes())?;
            let result = json!({
                "html_path": output_path.to_string_lossy(),
                "launch_url": output_path.to_string_lossy(),
                "local_api_url": Value::Null,
                "side_effect_executed": true
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("wrote reviewer console {}", output_path.display());
            }
        }
        UiCommand::Serve {
            bind,
            port,
            file,
            json,
        } => {
            let root = find_workspace_root(env::current_dir()?)?;
            let file = resolve_workspace_output_path(&root, &file, "ui file")?;
            let result = json!({
                "mode": "static_demo_console",
                "listen_addr": format!("{bind}:{port}"),
                "file": file.to_string_lossy(),
                "local_api_url": Value::Null,
                "side_effect_executed": false
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("serve static reviewer console {}", file.display());
            }
        }
    }
    Ok(())
}

fn run_approval_command(command: ApprovalCommand) -> anyhow::Result<()> {
    match command {
        ApprovalCommand::Pending { json } => {
            let approvals: Vec<_> = read_all_approvals()?
                .into_iter()
                .filter(|approval| approval.state == ApprovalState::Pending)
                .collect();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "approvals": approvals }))?
                );
            } else {
                for approval in approvals {
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
    }
    Ok(())
}

fn run_authority_command(command: AuthorityCommand) -> anyhow::Result<()> {
    match command {
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
    }
    Ok(())
}

struct CliProviderCallInput<'a> {
    session_id: &'a str,
    actor_id: Option<String>,
    authz_id: Option<String>,
    session_manifest: Option<&'a SessionManifest>,
    provider: &'a str,
    input: Option<&'a PathBuf>,
    root: Option<&'a PathBuf>,
    trace: Option<&'a PathBuf>,
    report: Option<&'a PathBuf>,
    format: Option<&'a str>,
}

fn provider_call_from_cli(input: CliProviderCallInput<'_>) -> ProviderCall {
    let mut arguments = serde_json::Map::new();
    if let Some(path) = input.input {
        arguments.insert(
            "input_path".to_string(),
            Value::String(path.to_string_lossy().into_owned()),
        );
    }
    if let Some(path) = input.root {
        let root_value = path.to_string_lossy().into_owned();
        let key = if input.session_manifest.is_some_and(|session_manifest| {
            session_manifest
                .roots
                .iter()
                .any(|root| root.name == root_value)
        }) {
            "root"
        } else {
            "root_path"
        };
        arguments.insert(key.to_string(), Value::String(root_value));
    }
    if let Some(path) = input.trace {
        arguments.insert(
            "trace_path".to_string(),
            Value::String(path.to_string_lossy().into_owned()),
        );
    }
    if let Some(path) = input.report {
        arguments.insert(
            "report_path".to_string(),
            Value::String(path.to_string_lossy().into_owned()),
        );
    }
    if let Some(format) = input.format {
        arguments.insert("format".to_string(), Value::String(format.to_string()));
    }

    ProviderCall {
        session_id: input.session_id.to_string(),
        provider: input.provider.to_string(),
        action: provider_action(input.provider).to_string(),
        arguments: Value::Object(arguments),
        actor_id: input.actor_id,
        authz_id: input.authz_id,
        approval_id: None,
    }
}

fn emit_provider_policy_outcome(outcome: &ProviderOutcome, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(outcome)?);
    } else {
        println!(
            "provider call {}: {}",
            serde_json::to_string(&outcome.decision)?,
            outcome.envelope.reason
        );
    }
    Ok(())
}

#[derive(Debug, Default)]
struct ResolvedProviderArgumentPaths {
    input: Option<PathBuf>,
    trace: Option<PathBuf>,
    report: Option<PathBuf>,
}

fn resolve_session_provider_argument_paths(
    session_manifest: &SessionManifest,
    call: &mut ProviderCall,
) -> anyhow::Result<ResolvedProviderArgumentPaths> {
    let Some(arguments) = call.arguments.as_object_mut() else {
        return Ok(ResolvedProviderArgumentPaths::default());
    };
    let selected_root = arguments
        .get("root")
        .and_then(Value::as_str)
        .and_then(|root_name| {
            session_manifest
                .roots
                .iter()
                .find(|root| root.name == root_name)
                .map(|root| root.path.clone())
        });
    let implicit_root = if selected_root.is_none() && session_manifest.roots.len() == 1 {
        Some(session_manifest.roots[0].path.clone())
    } else {
        None
    };
    let scoped_root = selected_root
        .or(implicit_root)
        .map(|root| absolute_cli_path(&root))
        .transpose()?;

    let input = resolve_session_provider_path_field(arguments, "input_path", scoped_root.as_ref())?;
    let trace = resolve_session_provider_path_field(arguments, "trace_path", scoped_root.as_ref())?;
    let report =
        resolve_session_provider_path_field(arguments, "report_path", scoped_root.as_ref())?;

    Ok(ResolvedProviderArgumentPaths {
        input,
        trace,
        report,
    })
}

fn resolve_session_provider_path_field(
    arguments: &mut serde_json::Map<String, Value>,
    field: &str,
    scoped_root: Option<&PathBuf>,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(path_text) = arguments
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
    else {
        return Ok(None);
    };
    let path = PathBuf::from(path_text);
    let resolved = if path.is_absolute() {
        path
    } else {
        let Some(scoped_root) = scoped_root else {
            anyhow::bail!(
                "session relative provider path {field} requires a scoped --root or exactly one session root"
            );
        };
        scoped_root.join(path)
    };
    arguments.insert(
        field.to_string(),
        Value::String(resolved.to_string_lossy().into_owned()),
    );
    Ok(Some(resolved))
}

fn bind_cli_file_digests(call: &mut ProviderCall) -> anyhow::Result<()> {
    let Some(arguments) = call.arguments.as_object_mut() else {
        return Ok(());
    };
    for &field in provider_path_digest_fields() {
        let Some(path) = arguments.get(field).and_then(Value::as_str) else {
            continue;
        };
        let digest = digest_file(Path::new(path))?;
        arguments.insert(format!("{field}_sha256"), Value::String(digest));
    }
    Ok(())
}

fn verify_cli_file_digests(call: &ProviderCall) -> anyhow::Result<()> {
    let Some(arguments) = call.arguments.as_object() else {
        return Ok(());
    };
    for &field in provider_path_digest_fields() {
        let Some(path) = arguments.get(field).and_then(Value::as_str) else {
            continue;
        };
        let digest_key = format!("{field}_sha256");
        let Some(expected) = arguments.get(&digest_key).and_then(Value::as_str) else {
            continue;
        };
        let actual = digest_file(Path::new(path))?;
        if actual != expected {
            anyhow::bail!("{field} changed after approval binding");
        }
    }
    Ok(())
}

fn provider_path_digest_fields() -> &'static [&'static str] {
    &["input_path", "trace_path", "report_path"]
}

fn digest_file(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path)?;
    Ok(hex_sha256(&bytes))
}

fn cli_provider_policy(
    session_manifest: Option<&SessionManifest>,
    provider: &str,
    input: Option<&PathBuf>,
    root: Option<&PathBuf>,
    trace: Option<&PathBuf>,
    report: Option<&PathBuf>,
) -> KernelPolicy {
    session_manifest
        .map(SessionManifest::to_kernel_policy)
        .unwrap_or_else(|| default_cli_provider_policy(provider, input, root, trace, report))
}

fn default_cli_provider_policy(
    provider: &str,
    input: Option<&PathBuf>,
    root: Option<&PathBuf>,
    trace: Option<&PathBuf>,
    report: Option<&PathBuf>,
) -> KernelPolicy {
    let mut policy = KernelPolicy::default();
    policy.allow_provider(provider);
    policy.active_assessment = true;
    for (name, path) in [
        ("input", input),
        ("root", root),
        ("trace", trace),
        ("report", report),
    ] {
        if let Some(root) = default_cli_scoped_root(path) {
            policy.add_scoped_root(ScopedRoot::new(format!("cli-{name}"), root));
        }
    }
    policy
}

fn default_cli_scoped_root(path: Option<&PathBuf>) -> Option<PathBuf> {
    let path = path?;
    if path.is_dir() {
        Some(path.clone())
    } else {
        path.parent().map(Path::to_path_buf)
    }
}

fn provider_action(provider: &str) -> &str {
    provider.rsplit('.').next().unwrap_or("call")
}

fn attach_matching_approval(call: &mut ProviderCall) -> anyhow::Result<()> {
    let binding = cli_approval_binding(call)?;
    if let Some(approval) = read_all_approvals()?
        .into_iter()
        .find(|approval| approval.binding == binding && approval_is_usable_for_cli(approval))
    {
        call.approval_id = Some(approval.approval_id);
    }
    Ok(())
}

fn approval_is_usable_for_cli(approval: &ApprovalRecord) -> bool {
    approval.state == ApprovalState::Approved
        && approval
            .expires_at
            .is_none_or(|expires_at| expires_at > OffsetDateTime::now_utc())
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

fn provider_is_external(provider: &str) -> bool {
    full_provider_registry()
        .get(provider)
        .is_some_and(|record| record.class == ProviderClass::External)
}

fn call_first_party_provider(
    provider: &str,
    input: Option<PathBuf>,
    trace: Option<PathBuf>,
    report: Option<PathBuf>,
    format: Option<String>,
) -> anyhow::Result<Value> {
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
            if verification["verified"].as_bool() != Some(true) {
                return Ok(json!({
                    "provider": provider,
                    "decision": "denied",
                    "execution_status": "failed",
                    "side_effect_executed": false,
                    "output": { "verification": verification }
                }));
            }
            Ok(json!({
                "provider": provider,
                "decision": "allowed",
                "execution_status": "completed",
                "side_effect_executed": false,
                "output": {
                    "verification": verification,
                    "events": events
                }
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
        other => anyhow::bail!("unsupported first-party provider call: {other}"),
    }
}

fn call_external_provider(provider: &str) -> Value {
    json!({
        "provider": provider,
        "decision": "allowed",
        "execution_status": "completed",
        "simulated": true,
        "side_effect_executed": false,
        "output": {
            "message": "contest demo provider execution is simulated after Rust policy allow"
        }
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct DemoProviderCall {
    provider: String,
    action: String,
    decision: String,
    execution_status: String,
    #[serde(default)]
    side_effect_executed: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    error_kind: Option<String>,
    #[serde(default)]
    obs_ref: Option<String>,
    #[serde(default)]
    arguments: Value,
}

fn run_demo_scenario(root: &Path, scenario: &str, output: &Path) -> anyhow::Result<Value> {
    ensure_contest_scenario(scenario)?;
    let scenario_path = root.join("scenarios").join(scenario);
    ensure_required_scenario_files(&scenario_path)?;
    let output_path = resolve_workspace_output_path(root, output, "demo output")?;
    fs::create_dir_all(&output_path)?;

    let provider_calls =
        read_demo_provider_calls(&scenario_path.join("expected/provider-calls.json"))?;
    let denials = read_json_value(&scenario_path.join("expected/denials.json"))?;
    let report = read_report(&scenario_path.join("expected/report.json"))?;
    let baseline = read_json_value(&scenario_path.join("expected/eval-baseline.json"))?;
    let trace_events = trace_events_for_scenario(scenario, &scenario_path, &provider_calls)?;
    let lint = lint_report_against_trace(&report, &trace_events);
    if !lint.ok {
        anyhow::bail!("scenario report does not lint against generated trace");
    }

    let metrics = evaluate_report_assurance(
        &report,
        &trace_events,
        trace_events.iter().map(|event| event.obs_id.clone()),
        EvalThresholds::strict(),
    );
    let webui = json!({
        "scenario": scenario,
        "trace": trace_events,
        "provider_calls": provider_calls,
        "denials": denials,
        "report": report,
        "metrics": metrics.metrics,
        "lint": lint,
        "expected": baseline,
        "side_effect_executed": false
    });

    write_json_file(&output_path.join("trace.json"), &webui["trace"])?;
    write_json_file(
        &output_path.join("provider-calls.json"),
        &webui["provider_calls"],
    )?;
    write_json_file(&output_path.join("denials.json"), &webui["denials"])?;
    write_json_file(&output_path.join("report.json"), &webui["report"])?;
    write_json_file(&output_path.join("metrics.json"), &webui["metrics"])?;
    write_json_file(&output_path.join("webui.json"), &webui)?;

    Ok(json!({
        "scenario": scenario,
        "output_dir": output_path.to_string_lossy(),
        "trace_path": output_path.join("trace.json").to_string_lossy(),
        "report_path": output_path.join("report.json").to_string_lossy(),
        "provider_call_count": provider_calls.len(),
        "denial_count": denials.as_array().map_or(0, Vec::len),
        "side_effect_executed": true
    }))
}

fn evaluate_scenario_corpora(root: &Path, suite: &Path) -> anyhow::Result<Value> {
    let suite_path = if suite.is_absolute() {
        suite.to_path_buf()
    } else {
        root.join(suite)
    };
    let mut cases = Vec::new();
    let mut passed = true;
    for scenario in CONTEST_SCENARIOS {
        let scenario_path = suite_path.join(scenario);
        let case = evaluate_scenario_case(scenario, &scenario_path)?;
        if case["passed"].as_bool() != Some(true) {
            passed = false;
        }
        cases.push(case);
    }

    Ok(json!({
        "suite": "contest-red-team-scenarios",
        "passed": passed,
        "case_count": cases.len(),
        "required_scenarios": CONTEST_SCENARIOS,
        "cases": cases,
        "side_effect_executed": false
    }))
}

fn evaluate_scenario_case(scenario: &str, scenario_path: &Path) -> anyhow::Result<Value> {
    let mut failures = Vec::new();
    if let Err(err) = ensure_required_scenario_files(scenario_path) {
        failures.push(err.to_string());
        return Ok(json!({
            "id": scenario,
            "passed": false,
            "failures": failures,
            "side_effect_executed": false
        }));
    }

    let provider_calls =
        read_demo_provider_calls(&scenario_path.join("expected/provider-calls.json"))?;
    let denials = read_json_array(&scenario_path.join("expected/denials.json"))?;
    let obs_refs = read_obs_refs(&scenario_path.join("expected/obs-refs.json"))?;
    let report = read_report(&scenario_path.join("expected/report.json"))?;
    let baseline = read_json_value(&scenario_path.join("expected/eval-baseline.json"))?;
    let trace_events = trace_events_for_scenario(scenario, scenario_path, &provider_calls)?;
    let eval = evaluate_report_assurance(
        &report,
        &trace_events,
        obs_refs.clone(),
        EvalThresholds::strict(),
    );
    failures.extend(eval.failures.clone());
    failures.extend(validate_scenario_expectations(
        &provider_calls,
        &denials,
        &obs_refs,
        &trace_events,
        &baseline,
    ));
    failures.sort();
    failures.dedup();
    let passed = failures.is_empty();

    Ok(json!({
        "id": scenario,
        "passed": passed,
        "obs_refs": obs_refs,
        "denial_count": denials.len(),
        "requires_review_count": provider_calls.iter().filter(|call| call.decision == "requires_review").count(),
        "provider_call_count": provider_calls.len(),
        "metrics": eval.metrics,
        "failures": failures,
        "side_effect_executed": false
    }))
}

fn validate_scenario_expectations(
    provider_calls: &[DemoProviderCall],
    denials: &[Value],
    obs_refs: &[String],
    trace_events: &[TraceEvent],
    baseline: &Value,
) -> Vec<String> {
    let mut failures = Vec::new();
    if provider_calls.is_empty() {
        failures.push("expected_provider_calls_empty".to_string());
    }
    if denials.is_empty() {
        failures.push("expected_denials_empty".to_string());
    }
    if obs_refs.is_empty() {
        failures.push("expected_obs_refs_empty".to_string());
    }
    if trace_events.len() != obs_refs.len() {
        failures.push("trace_event_count_does_not_match_obs_refs".to_string());
    }
    let expected_denials = baseline
        .get("expected_denials")
        .and_then(Value::as_u64)
        .unwrap_or(denials.len() as u64);
    if expected_denials != denials.len() as u64 {
        failures.push("denial_count_does_not_match_baseline".to_string());
    }
    let expected_reviews = baseline
        .get("expected_requires_review")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            provider_calls
                .iter()
                .filter(|call| call.decision == "requires_review")
                .count() as u64
        });
    let actual_reviews = provider_calls
        .iter()
        .filter(|call| call.decision == "requires_review")
        .count() as u64;
    if expected_reviews != actual_reviews {
        failures.push("requires_review_count_does_not_match_baseline".to_string());
    }
    for call in provider_calls {
        if !matches!(
            call.decision.as_str(),
            "allowed" | "denied" | "requires_review"
        ) {
            failures.push(format!("invalid_provider_decision:{}", call.provider));
        }
        if matches!(call.decision.as_str(), "denied" | "requires_review")
            && call.side_effect_executed
        {
            failures.push(format!(
                "blocked_call_executed_side_effect:{}",
                call.provider
            ));
        }
    }
    failures
}

fn trace_events_for_scenario(
    scenario: &str,
    scenario_path: &Path,
    provider_calls: &[DemoProviderCall],
) -> anyhow::Result<Vec<TraceEvent>> {
    let obs_refs = read_obs_refs(&scenario_path.join("expected/obs-refs.json"))?;
    let mut store = InMemoryTraceStore::default();
    for (idx, call) in provider_calls.iter().enumerate() {
        let obs_id = call
            .obs_ref
            .clone()
            .or_else(|| obs_refs.get(idx).cloned())
            .ok_or_else(|| anyhow::anyhow!("missing obs ref for provider call {}", idx + 1))?;
        let event_type = match call.decision.as_str() {
            "allowed" => "provider_completed",
            "requires_review" => "provider_approval_pending",
            "denied" => "provider_denied",
            _ => "provider_failed",
        };
        store.append_signed(
            obs_id,
            event_type.to_string(),
            Some(call.provider.clone()),
            json!({
                "scenario": scenario,
                "provider": call.provider,
                "action": call.action,
                "decision": call.decision,
                "execution_status": call.execution_status,
                "reason": call.reason,
                "error_kind": call.error_kind,
                "side_effect_executed": call.side_effect_executed
            }),
        );
    }
    Ok(store
        .query(TraceQuery {
            limit: provider_calls.len().max(1),
            ..TraceQuery::default()
        })
        .events)
}

fn render_scenario_suite_report(
    root: &Path,
    suite: &Path,
    format: RenderFormat,
) -> anyhow::Result<runwarden_assurance::report::RenderedReport> {
    let suite_path = if suite.is_absolute() {
        suite.to_path_buf()
    } else {
        root.join(suite)
    };
    let eval = evaluate_scenario_corpora(root, suite)?;
    let mut markdown = String::from("# Runwarden Contest Report\n\n");
    markdown.push_str("## Scenario Metrics\n\n");
    markdown.push_str("| Scenario | Denials | Reviews | Provider Calls | Passed |\n");
    markdown.push_str("| --- | ---: | ---: | ---: | --- |\n");
    for case in eval["cases"].as_array().into_iter().flatten() {
        markdown.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            case["id"].as_str().unwrap_or("unknown"),
            case["denial_count"].as_u64().unwrap_or(0),
            case["requires_review_count"].as_u64().unwrap_or(0),
            case["provider_call_count"].as_u64().unwrap_or(0),
            case["passed"].as_bool().unwrap_or(false)
        ));
    }
    markdown.push('\n');

    for scenario in CONTEST_SCENARIOS {
        let scenario_path = suite_path.join(scenario);
        let report = read_report(&scenario_path.join("expected/report.json"))?;
        markdown.push_str(&format!("## {}\n\n", scenario));
        for claim in report.claims {
            markdown.push_str(&format!(
                "- {}: {} ({})\n",
                claim.id,
                claim.text,
                claim.obs_refs.join(", ")
            ));
        }
        markdown.push('\n');
    }

    match format {
        RenderFormat::Markdown => Ok(runwarden_assurance::report::RenderedReport {
            extension: "md".to_string(),
            contents: markdown,
            side_effect_executed: false,
        }),
        RenderFormat::Html => Ok(runwarden_assurance::report::RenderedReport {
            extension: "html".to_string(),
            contents: format!(
                "<article><h1>Runwarden Contest Report</h1><pre>{}</pre></article>",
                html_escape(&markdown)
            ),
            side_effect_executed: false,
        }),
        RenderFormat::Json => Ok(runwarden_assurance::report::RenderedReport {
            extension: "json".to_string(),
            contents: serde_json::to_string_pretty(&eval)?,
            side_effect_executed: false,
        }),
        RenderFormat::Sarif => anyhow::bail!("scenario-suite render does not support SARIF"),
    }
}

fn render_static_demo_console(input: &Path) -> anyhow::Result<String> {
    let mut scenario_files = Vec::new();
    if input.is_file() {
        scenario_files.push(input.to_path_buf());
    } else if input.exists() {
        for entry in fs::read_dir(input)? {
            let entry = entry?;
            let candidate = entry.path().join("webui.json");
            if candidate.exists() {
                scenario_files.push(candidate);
            }
        }
    }
    scenario_files.sort();

    let mut html = String::from(
        "<!doctype html><meta charset=\"utf-8\"><title>Runwarden Reviewer Console</title><main><h1>Runwarden Reviewer Console</h1>",
    );
    if scenario_files.is_empty() {
        html.push_str("<p>No demo JSON loaded.</p>");
    }
    for file in scenario_files {
        let value = read_json_value(&file)?;
        let scenario = value["scenario"].as_str().unwrap_or("unknown");
        let provider_count = value["provider_calls"].as_array().map_or(0, Vec::len);
        let denial_count = value["denials"].as_array().map_or(0, Vec::len);
        html.push_str(&format!(
            "<section><h2>{}</h2><p>Provider calls: {}</p><p>Denials: {}</p><p>Trace: verified input required before report use</p></section>",
            html_escape(scenario),
            provider_count,
            denial_count
        ));
    }
    html.push_str("</main>");
    Ok(html)
}

fn ensure_contest_scenario(scenario: &str) -> anyhow::Result<()> {
    if CONTEST_SCENARIOS.contains(&scenario) {
        Ok(())
    } else {
        anyhow::bail!("unknown contest scenario: {scenario}");
    }
}

fn ensure_required_scenario_files(path: &Path) -> anyhow::Result<()> {
    let mut missing = Vec::new();
    for relative in scenario_required_files() {
        if !path.join(relative).exists() {
            missing.push(*relative);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "{} missing required scenario files: {}",
            path.display(),
            missing.join(", ")
        );
    }
}

fn scenario_required_files() -> &'static [&'static str] {
    &[
        "README.md",
        "manifests/assessment.toml",
        "attacks/prompt-injection.md",
        "benign/request.md",
        "agent/script.json",
        "expected/denials.json",
        "expected/provider-calls.json",
        "expected/obs-refs.json",
        "expected/report.json",
        "expected/eval-baseline.json",
    ]
}

fn read_demo_provider_calls(path: &Path) -> anyhow::Result<Vec<DemoProviderCall>> {
    let value = read_json_value(path)?;
    let calls = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{} must contain a JSON array", path.display()))?;
    calls
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)
}

fn read_obs_refs(path: &Path) -> anyhow::Result<Vec<String>> {
    read_json_array(path)?
        .into_iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| anyhow::anyhow!("{} contains a non-string obs ref", path.display()))
        })
        .collect()
}

fn read_json_array(path: &Path) -> anyhow::Result<Vec<Value>> {
    let value = read_json_value(path)?;
    value
        .as_array()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("{} must contain a JSON array", path.display()))
}

fn read_json_value(path: &Path) -> anyhow::Result<Value> {
    let body = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&body)?)
}

fn write_json_file(path: &Path, value: &Value) -> anyhow::Result<()> {
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(value)?))?;
    Ok(())
}

fn read_report(path: &Path) -> anyhow::Result<ReportDraft> {
    let content = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&content)?)
}

fn read_trace(path: &Path) -> anyhow::Result<Vec<TraceEvent>> {
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

fn assessment_with_manifest_relative_roots(
    manifest: &Path,
    mut assessment: AssessmentManifest,
) -> anyhow::Result<AssessmentManifest> {
    let manifest_dir = manifest.parent().unwrap_or_else(|| Path::new("."));
    let manifest_dir = absolute_cli_path(manifest_dir)?;
    for root in &mut assessment.roots {
        if !root.path.is_absolute() {
            root.path = manifest_dir.join(&root.path);
        }
    }
    Ok(assessment)
}

fn absolute_cli_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
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
    let value: Value = serde_json::from_str(arguments)?;
    Ok(hex_sha256(&serde_json::to_vec(&value)?))
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

fn resolve_workspace_output_path(
    root: &Path,
    requested: &Path,
    label: &str,
) -> anyhow::Result<PathBuf> {
    if requested.as_os_str().is_empty()
        || requested.is_absolute()
        || requested.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
            )
        })
    {
        anyhow::bail!("{label} path must be a relative path inside the workspace");
    }

    reject_symlink_components(root, requested, label)?;
    let output_path = root.join(requested);
    if !path_is_within_root(&output_path, root) {
        anyhow::bail!("{label} path must be a relative path inside the workspace");
    }
    Ok(output_path)
}

fn reject_symlink_components(root: &Path, requested: &Path, label: &str) -> anyhow::Result<()> {
    let mut current = root.to_path_buf();
    for component in requested.components() {
        let std::path::Component::Normal(part) = component else {
            anyhow::bail!("{label} path must be a relative path inside the workspace");
        };
        current.push(part);
        if fs::symlink_metadata(&current)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            anyhow::bail!("{label} path must not contain symlink components");
        }
    }
    Ok(())
}

fn path_is_within_root(candidate: &Path, root: &Path) -> bool {
    let Ok(canonical_root) = root.canonicalize() else {
        return false;
    };
    match candidate.canonicalize() {
        Ok(canonical_candidate) => canonical_candidate.starts_with(&canonical_root),
        Err(_) => canonical_existing_parent(candidate)
            .map(|parent| parent.starts_with(&canonical_root))
            .unwrap_or(false),
    }
}

fn canonical_existing_parent(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent()?.to_path_buf();
    loop {
        if fs::symlink_metadata(&current).is_ok() {
            return current.canonicalize().ok();
        }
        if !current.pop() {
            return None;
        }
    }
}

fn verify_trace_events(events: Vec<TraceEvent>) -> Value {
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
    for path in [
        "Cargo.toml",
        "package.json",
        "pnpm-workspace.yaml",
        "README.md",
        "docs/README.md",
        "docs/reference/cli.md",
        "docs/reference/mcp.md",
        "docs/reference/provider-model.md",
        "docs/reference/provider-integration.md",
        "docs/reference/evidence-and-accountability.md",
        "docs/reference/webui-review-console.md",
        "packages/webui/src/index.ts",
        "scripts/pr_fast_gate.sh",
        "scripts/release_gate_local.sh",
    ] {
        if !root.join(path).exists() {
            anyhow::bail!("strict check failed: missing {}", root.join(path).display());
        }
    }

    for scenario in CONTEST_SCENARIOS {
        ensure_required_scenario_files(&root.join("scenarios").join(scenario))?;
    }

    let local_gate = fs::read_to_string(root.join("scripts/release_gate_local.sh"))?;
    for command in [
        "runwarden eval scenarios --json",
        "runwarden demo run --scenario prompt-injection-file-exfil",
        "runwarden report render --scenario-suite scenarios",
    ] {
        if !local_gate.contains(command) {
            anyhow::bail!("strict check failed: contest gate does not run {command}");
        }
    }

    let scenario_eval = evaluate_scenario_corpora(&root, Path::new("scenarios"))?;
    if scenario_eval["passed"].as_bool() != Some(true) {
        anyhow::bail!("strict check failed: scenario eval did not pass");
    }

    println!("runwarden strict check passed");
    println!("- contest scenario corpus present");
    println!("- lean MCP/CLI reference docs present");
    println!("- static WebUI package present");
    println!("- contest gate scripts present");
    Ok(())
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

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
