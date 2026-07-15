use std::{
    env, fs,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand};
use runwarden_anomaly::{AnomalyMonitor, BehaviorProfile};
use runwarden_assurance::eval::{EvalThresholds, evaluate_report_assurance};
use runwarden_assurance::report::{
    RenderFormat, ReportDraft, lint_report_against_trace, render_report,
};
use runwarden_assurance::security_eval::{
    SecurityDecision, SecurityEvalCase, evaluate_security_cases,
};
use runwarden_kernel::artifact::resolve_workspace_relative_path;
use runwarden_kernel::contracts::{PolicyDecision, ProviderCall, ProviderClass, ProviderOutcome};
use runwarden_kernel::evidence::{InMemoryTraceStore, TraceEvent, TraceQuery, hex_sha256};
use runwarden_kernel::kernel::KernelEnforcer;
use runwarden_kernel::manifest::{AssessmentManifest, SessionManifest};
use runwarden_providers::catalog::full_provider_registry;
use runwarden_providers::input::{InputInspectPolicy, InputSource, inspect_input};
use runwarden_providers::tools;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

mod server;

const CONTEST_SCENARIOS: &[&str] = &[
    "prompt-injection-file-exfil",
    "tool-hijack-email-api",
    "memory-knowledge-poisoning",
    "environment-local-web-risk",
    "path-escape-file-boundary",
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
    Demo {
        #[arg(long)]
        scenario: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        upstream: Option<String>,
        #[arg(long, default_value_t = 8088)]
        port: u16,
        #[arg(long)]
        json: bool,
    },
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    Check {
        #[arg(long)]
        strict: bool,
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
        Command::Demo {
            scenario,
            all,
            output,
            upstream,
            port,
            json,
        } => run_demo_command(scenario, all, output, upstream, port, json)?,
        Command::Trace { command } => run_trace_command(command)?,
        Command::Report { command } => run_report_command(command)?,
        Command::Check { strict, json } => {
            if strict {
                run_strict_check(json)?;
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "passed": true,
                            "side_effect_executed": false
                        }))?
                    );
                } else {
                    println!("runwarden check passed");
                }
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

fn run_demo_command(
    scenario: Option<String>,
    all: bool,
    output: Option<PathBuf>,
    upstream: Option<String>,
    port: u16,
    json_output: bool,
) -> anyhow::Result<()> {
    if scenario.is_some() && all {
        anyhow::bail!("use either --scenario or --all, not both");
    }
    if let Some(scenario) = scenario {
        let output =
            output.ok_or_else(|| anyhow::anyhow!("--output is required with --scenario"))?;
        let root = find_workspace_root(env::current_dir()?)?;
        let result = run_demo_scenario_real(&root, &scenario, &output)?;
        if json_output {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "wrote demo scenario {} to {}",
                scenario,
                result["output_dir"].as_str().unwrap_or("<unknown>")
            );
        }
        return Ok(());
    }
    if all {
        let output = output.unwrap_or_else(|| PathBuf::from("artifacts/demo"));
        let root = find_workspace_root(env::current_dir()?)?;
        let output_path = resolve_workspace_output_path(&root, &output, "demo output")?;
        fs::create_dir_all(&output_path)?;
        let mut results = Vec::new();
        for scenario in CONTEST_SCENARIOS {
            results.push(run_demo_scenario_real(
                &root,
                scenario,
                &output.join(scenario),
            )?);
        }
        let html = server::render_static_console_for_scenarios(&output_path, CONTEST_SCENARIOS)?;
        fs::write(output_path.join("reviewer-console.html"), html)?;
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "scenarios": results,
                    "reviewer_console": output_path.join("reviewer-console.html").to_string_lossy(),
                    "side_effect_executed": true
                }))?
            );
        } else {
            println!("wrote demo suite to {}", output_path.to_string_lossy());
        }
        return Ok(());
    }
    run_demo_interactive(upstream, port, json_output)
}

fn run_demo_interactive(
    upstream: Option<String>,
    port: u16,
    json_output: bool,
) -> anyhow::Result<()> {
    let root = find_workspace_root(env::current_dir()?)?;
    let run_id = format!(
        "demo-{}-{}",
        time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
        std::process::id()
    );
    let state_dir = root.join(".runwarden").join("runs").join(run_id);
    fs::create_dir_all(&state_dir)?;
    let trace_path = state_dir.join("model-events.jsonl");

    // Set RUNWARDEN_STATE_DIR so the MCP subprocess (spawned by opencode)
    // writes all evidence and authority state into this fresh, run-scoped
    // directory. This prevents stale approvals, locks, or trace rows from a
    // previous demonstration from entering the current evidence set.
    // SAFETY: single-threaded setup before spawning proxy thread and server.
    unsafe {
        std::env::set_var("RUNWARDEN_STATE_DIR", &state_dir);
    }

    let proxy_client_token = generate_proxy_client_token()?;
    // SAFETY: single-threaded setup before spawning the proxy or console.
    unsafe {
        std::env::set_var("RUNWARDEN_PROXY_CLIENT_TOKEN", proxy_client_token);
    }
    start_llm_proxy_thread(upstream, trace_path.clone())?;

    let (tx, _rx) = tokio::sync::broadcast::channel::<server::DemoEvent>(256);
    server::watch_jsonl_events(trace_path.clone(), "model_call", tx.clone());
    server::watch_jsonl_events(state_dir.join("events.jsonl"), "provider_call", tx.clone());

    let state = server::AppState {
        event_tx: tx,
        state_dir,
        trace_path,
    };
    server::run_console_server("127.0.0.1", port, state, json_output)
}

fn generate_proxy_client_token() -> anyhow::Result<String> {
    for _ in 0..8 {
        let mut secret = [0_u8; 32];
        getrandom::fill(&mut secret)?;
        let token = secret
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if token
            .as_bytes()
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            >= 8
        {
            return Ok(token);
        }
    }
    anyhow::bail!("operating-system randomness did not produce a suitable proxy capability")
}

fn start_llm_proxy_thread(upstream: Option<String>, trace_path: PathBuf) -> anyhow::Result<()> {
    // Note: proxy port 8787 is fixed to match opencode.runwarden-only.json
    // baseURL. If port 8787 is in use, add a --proxy-port flag.
    let cli = runwarden_llm_proxy::Cli {
        bind: "127.0.0.1".to_string(),
        port: 8787,
        upstream: upstream.unwrap_or_else(|| "https://api.opencode.ai/v1".to_string()),
        api_key_env: "RUNWARDEN_LLM_API_KEY".to_string(),
        client_token_env: "RUNWARDEN_PROXY_CLIENT_TOKEN".to_string(),
        trace: trace_path.to_string_lossy().to_string(),
        max_body_bytes: 8 * 1024 * 1024,
    };
    // Reserve the actual listening socket before the reviewer service is
    // announced. If 8787 is occupied, the whole demo fails closed here.
    let listener = runwarden_llm_proxy::bind_listener(&cli)?;
    std::thread::Builder::new()
        .name("runwarden-llm-proxy".to_string())
        .spawn(move || {
            if let Err(err) = runwarden_llm_proxy::serve_with_listener(cli, listener) {
                eprintln!("llm proxy error: {err}");
            }
        })?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct ProviderCallResult {
    provider: String,
    action: String,
    decision: String,
    execution_status: String,
    defense_layer: String,
    side_effect_executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    obs_ref: Option<String>,
    arguments: Value,
    output: Value,
    anomaly: Value,
    trace_event: Value,
}

fn run_demo_scenario_real(root: &Path, scenario: &str, output: &Path) -> anyhow::Result<Value> {
    ensure_contest_scenario(scenario)?;
    let scenario_path = root.join("scenarios").join(scenario);
    ensure_required_scenario_files(&scenario_path)?;
    let output_path = resolve_workspace_output_path(root, output, "demo output")?;
    fs::create_dir_all(&output_path)?;

    let manifest_path = scenario_path.join("manifests/assessment.toml");
    let manifest_body = fs::read_to_string(&manifest_path)?;
    let assessment = AssessmentManifest::from_toml_str(&manifest_body)?;
    let assessment = assessment_with_manifest_relative_roots(&manifest_path, assessment)?;
    let session = SessionManifest::from_assessment(scenario.to_string(), &assessment);
    let expected_calls =
        read_demo_provider_calls(&scenario_path.join("expected/provider-calls.json"))?;
    let agent_steps = read_agent_script(&scenario_path.join("agent/script.json"))?;
    let story_failures = validate_scenario_story(&scenario_path, &expected_calls, &agent_steps);
    if !story_failures.is_empty() {
        anyhow::bail!(
            "scenario attack story is invalid: {}",
            story_failures.join(", ")
        );
    }
    let attack_input_path = agent_steps
        .first()
        .and_then(|step| step.arguments.get("input_path"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let attack_fixture = resolve_attack_fixture(&scenario_path, attack_input_path)?;
    let attack_prompt = fs::read_to_string(&attack_fixture)?;
    let attack_sha256 = hex_sha256(attack_prompt.as_bytes());
    let sandbox_root = tools::sandbox_root_from();
    let mut previous_hash = None;
    let mut previous_obs_id: Option<String> = None;
    let mut anomaly_monitor = AnomalyMonitor::new(BehaviorProfile::default_benign());
    let mut trace_events = Vec::new();
    let mut results = Vec::new();

    for (input, expected) in agent_steps.iter().zip(&expected_calls) {
        let mut result =
            execute_provider_call_real(&session, input, &scenario_path, &sandbox_root)?;
        let argument_bytes = serde_json::to_vec(&input.arguments)?.len();
        let egress_host = demo_egress_host(&input.arguments);
        let anomaly_report =
            anomaly_monitor.preview(&input.provider, argument_bytes, egress_host.as_deref());
        result.anomaly = serde_json::to_value(&anomaly_report)?;
        if result.decision == "allowed" && result.execution_status != "failed" {
            anomaly_monitor.analyze(&input.provider, argument_bytes, egress_host.as_deref());
        }
        let event_type = match result.decision.as_str() {
            "allowed" if result.execution_status == "simulated" => "provider_simulated_replay",
            "allowed" => "provider_completed",
            "denied" => "provider_denied",
            "requires_review" => "provider_approval_pending",
            _ => "provider_failed",
        };
        let obs_id = expected.obs_ref.clone().unwrap_or_else(|| {
            result
                .obs_ref
                .clone()
                .unwrap_or_else(|| "obs_demo".to_string())
        });
        result.obs_ref = Some(obs_id.clone());
        let trace_event = TraceEvent::sealed(
            obs_id,
            event_type.to_string(),
            Some(result.provider.clone()),
            json!({
                "scenario": scenario,
                "attack_id": scenario,
                "source_sha256": &attack_sha256,
                "parent_obs_id": &previous_obs_id,
                "actor_id": &session.actor_id,
                "provider": &result.provider,
                "action": &result.action,
                "decision": &result.decision,
                "execution_status": &result.execution_status,
                "reason": &result.reason,
                "error_kind": &result.error_kind,
                "arguments": &result.arguments,
                "anomaly": &result.anomaly,
                "side_effect_executed": result.side_effect_executed,
                "simulated": result.execution_status == "simulated"
            }),
            previous_hash,
        );
        previous_hash = Some(trace_event.event_hash.clone());
        previous_obs_id = Some(trace_event.obs_id.clone());
        result.trace_event = serde_json::to_value(&trace_event)?;
        trace_events.push(trace_event);
        results.push(result);
    }

    let expected_denials = read_json_value(&scenario_path.join("expected/denials.json"))?;
    validate_provider_results(&results, &expected_calls)?;
    validate_denials(&results, &expected_denials)?;
    let report = read_report(&scenario_path.join("expected/report.json"))?;
    let baseline = read_json_value(&scenario_path.join("expected/eval-baseline.json"))?;
    let trace_verification = verify_trace_events(trace_events.clone());
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
    // Score one complete attack story, rather than inflating the sample count
    // by treating every tool step as a separate attack. The expected outcome
    // is derived from the oracle; the actual outcome is independently derived
    // from the calls that were executed above.
    let expected_attack_decision = aggregate_expected_attack_story(&expected_calls)?;
    let actual_attack_decision = aggregate_actual_attack_story(&results)?;
    let attack_side_effect_executed = results
        .iter()
        .skip(1)
        .any(|result| result.side_effect_executed);

    // Execute a distinct benign fixture through the same kernel and
    // runwarden.input.inspect provider. The expected label is the independent
    // semantic definition of this control (benign input must be allowed),
    // while the actual decision and risk output come from this invocation.
    let benign_input_path = "benign/request.md";
    let benign_fixture = scenario_path.join(benign_input_path);
    let benign_prompt = fs::read_to_string(&benign_fixture)?;
    let benign_oracle = expected_calls
        .first()
        .ok_or_else(|| anyhow::anyhow!("attack story has no input-inspection oracle"))?;
    anyhow::ensure!(
        benign_oracle.provider == "runwarden.input.inspect",
        "benign control cannot reuse the inspection path: first attack step is not input.inspect"
    );
    let benign_step = DemoAgentStep {
        provider: benign_oracle.provider.clone(),
        action: benign_oracle.action.clone(),
        arguments: json!({"input_path": benign_input_path}),
    };
    let benign_result =
        execute_provider_call_real(&session, &benign_step, &scenario_path, &sandbox_root)?;
    let expected_benign_decision = SecurityDecision::Allowed;
    let actual_benign_decision = parse_security_decision(&benign_result.decision)?;
    let benign_risk_count = benign_result
        .output
        .get("risks")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    anyhow::ensure!(
        benign_risk_count == 0,
        "benign control produced {benign_risk_count} inspection risk finding(s)"
    );

    let security_cases = vec![
        SecurityEvalCase::new(
            format!("{scenario}-attack-story"),
            true,
            expected_attack_decision,
            actual_attack_decision,
            attack_side_effect_executed,
        ),
        SecurityEvalCase::new(
            format!("{scenario}-benign-control"),
            false,
            expected_benign_decision,
            actual_benign_decision,
            benign_result.side_effect_executed,
        ),
    ];
    let security_metrics = evaluate_security_cases(&security_cases);
    anyhow::ensure!(
        security_metrics.passed,
        "scenario security metrics failed: {}",
        security_metrics.failures.join(", ")
    );
    let provider_calls_value = serde_json::to_value(&results)?;
    let webui = json!({
        "scenario": scenario,
        "story": {
            "attack_id": scenario,
            "input_path": attack_input_path,
            "input_sha256": attack_sha256,
            "attack_prompt": attack_prompt,
            "agent_script": agent_steps,
            "driver": "deterministic_agent_script",
            "oracle": "expected/provider-calls.json"
        },
        "trace": trace_events,
        "provider_calls": provider_calls_value,
        "denials": expected_denials,
        "report": report,
        "metrics": metrics.metrics,
        "security_metrics": security_metrics,
        "security_evaluation": {
            "method": "one_attack_story_plus_independent_benign_control",
            "cases": security_cases,
            "attack_story": {
                "fixture": attack_input_path,
                "oracle_source": "expected/provider-calls.json (steps after input inspection)",
                "actual_source": "executed agent/script.json (steps after input inspection)",
                "aggregation": "allowed if any attack step was allowed or executed a side effect; otherwise denied if any step was denied; otherwise requires_review",
                "oracle_step_decisions": expected_calls.iter().skip(1).map(|call| call.decision.as_str()).collect::<Vec<_>>(),
                "actual_step_decisions": results.iter().skip(1).map(|result| result.decision.as_str()).collect::<Vec<_>>()
            },
            "benign_control": {
                "fixture": benign_input_path,
                "fixture_sha256": hex_sha256(benign_prompt.as_bytes()),
                "expected_decision": "allowed",
                "expected_decision_source": "independent benign-control semantic label",
                "actual_execution": "KernelEnforcer + runwarden.input.inspect over benign/request.md",
                "provider": &benign_result.provider,
                "action": &benign_result.action,
                "actual_decision": &benign_result.decision,
                "execution_status": &benign_result.execution_status,
                "inspection_risk_count": benign_risk_count,
                "side_effect_executed": benign_result.side_effect_executed
            }
        },
        "trace_verification": trace_verification,
        "lint": lint,
        "expected": baseline,
        "side_effect_executed": results.iter().any(|result| result.side_effect_executed)
    });

    write_json_file(&output_path.join("trace.json"), &webui["trace"])?;
    write_json_file(
        &output_path.join("provider-calls.json"),
        &webui["provider_calls"],
    )?;
    write_json_file(&output_path.join("denials.json"), &webui["denials"])?;
    write_json_file(&output_path.join("report.json"), &webui["report"])?;
    write_json_file(
        &output_path.join("metrics.json"),
        &json!({
            "assurance": &webui["metrics"],
            "security": &webui["security_metrics"]
        }),
    )?;
    write_json_file(&output_path.join("webui.json"), &webui)?;

    Ok(json!({
        "scenario": scenario,
        "output_dir": output_path.to_string_lossy(),
        "provider_call_count": results.len(),
        "denial_count": results.iter().filter(|result| result.decision == "denied").count(),
        "requires_review_count": results.iter().filter(|result| result.decision == "requires_review").count(),
        "side_effect_executed": webui["side_effect_executed"],
    }))
}

fn parse_security_decision(decision: &str) -> anyhow::Result<SecurityDecision> {
    match decision {
        "allowed" => Ok(SecurityDecision::Allowed),
        "denied" => Ok(SecurityDecision::Denied),
        "requires_review" => Ok(SecurityDecision::RequiresReview),
        _ => anyhow::bail!("unsupported security decision: {decision}"),
    }
}

fn aggregate_expected_attack_story(calls: &[DemoProviderCall]) -> anyhow::Result<SecurityDecision> {
    aggregate_attack_story_decision(
        calls
            .iter()
            .skip(1)
            .map(|call| (call.decision.as_str(), call.side_effect_executed)),
    )
}

fn aggregate_actual_attack_story(
    results: &[ProviderCallResult],
) -> anyhow::Result<SecurityDecision> {
    aggregate_attack_story_decision(
        results
            .iter()
            .skip(1)
            .map(|result| (result.decision.as_str(), result.side_effect_executed)),
    )
}

fn aggregate_attack_story_decision<'a>(
    decisions: impl Iterator<Item = (&'a str, bool)>,
) -> anyhow::Result<SecurityDecision> {
    let decisions = decisions.collect::<Vec<_>>();
    anyhow::ensure!(
        !decisions.is_empty(),
        "attack story must contain at least one post-inspection tool intent"
    );
    for (decision, _) in &decisions {
        parse_security_decision(decision)?;
    }
    if decisions
        .iter()
        .any(|(decision, side_effect)| *decision == "allowed" || *side_effect)
    {
        return Ok(SecurityDecision::Allowed);
    }
    if decisions.iter().any(|(decision, _)| *decision == "denied") {
        return Ok(SecurityDecision::Denied);
    }
    Ok(SecurityDecision::RequiresReview)
}

fn execute_provider_call_real(
    session: &SessionManifest,
    input: &DemoAgentStep,
    scenario_path: &Path,
    sandbox_root: &Path,
) -> anyhow::Result<ProviderCallResult> {
    let call = ProviderCall {
        session_id: session.session_id.clone(),
        provider: input.provider.clone(),
        action: input.action.clone(),
        arguments: input.arguments.clone(),
        actor_id: session.actor_id.clone(),
        authz_id: session.authz_id.clone(),
        approval_id: None,
    };
    let mut enforcer = KernelEnforcer::new(full_provider_registry(), session.to_kernel_policy());
    let outcome = enforcer.evaluate_call(&call);
    let obs_ref = Some(outcome.observation_id.clone());
    match outcome.decision {
        PolicyDecision::Denied => Ok(blocked_provider_result(input, &outcome, "denied", obs_ref)),
        PolicyDecision::RequiresReview => Ok(blocked_provider_result(
            input,
            &outcome,
            "requires_review",
            obs_ref,
        )),
        PolicyDecision::Allowed => {
            let executed = if provider_is_external(&input.provider) {
                call_external_provider(
                    &input.provider,
                    &input.action,
                    &input.arguments,
                    sandbox_root,
                )
            } else {
                let input_path = input
                    .arguments
                    .get("input_path")
                    .and_then(Value::as_str)
                    .map(|path| scenario_path.join(path));
                call_first_party_provider(&input.provider, input_path, None, None, None)?
            };
            Ok(ProviderCallResult {
                provider: input.provider.clone(),
                action: input.action.clone(),
                decision: "allowed".to_string(),
                execution_status: executed
                    .get("execution_status")
                    .and_then(Value::as_str)
                    .unwrap_or("completed")
                    .to_string(),
                side_effect_executed: executed
                    .get("side_effect_executed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                defense_layer: server::defense_layer_for(
                    Some(&input.provider),
                    Some("allowed"),
                    None,
                )
                .to_string(),
                error_kind: None,
                reason: Some(outcome.envelope.reason.clone()),
                obs_ref,
                arguments: input.arguments.clone(),
                output: executed.get("output").cloned().unwrap_or(Value::Null),
                anomaly: Value::Null,
                trace_event: Value::Null,
            })
        }
    }
}

fn blocked_provider_result(
    input: &DemoAgentStep,
    outcome: &ProviderOutcome,
    decision: &str,
    obs_ref: Option<String>,
) -> ProviderCallResult {
    let error_kind = outcome
        .envelope
        .error_kind
        .as_ref()
        .and_then(|kind| serde_json::to_value(kind).ok())
        .and_then(|value| value.as_str().map(ToString::to_string));
    ProviderCallResult {
        provider: input.provider.clone(),
        action: input.action.clone(),
        decision: decision.to_string(),
        execution_status: "not_executed".to_string(),
        defense_layer: server::defense_layer_for(
            Some(&input.provider),
            Some(decision),
            error_kind.as_deref(),
        )
        .to_string(),
        side_effect_executed: false,
        error_kind,
        reason: Some(outcome.envelope.reason.clone()),
        obs_ref,
        arguments: input.arguments.clone(),
        output: Value::Null,
        anomaly: Value::Null,
        trace_event: Value::Null,
    }
}

fn validate_denials(results: &[ProviderCallResult], expected: &Value) -> anyhow::Result<()> {
    let expected_arr = expected
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected denials must be array"))?;
    for expected_denial in expected_arr {
        let provider = expected_denial
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("expected denial missing provider"))?;
        let error_kind = expected_denial
            .get("error_kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("expected denial missing error_kind"))?;
        let found = results.iter().any(|result| {
            result.provider == provider
                && result.decision == "denied"
                && result.error_kind.as_deref() == Some(error_kind)
        });
        if !found {
            anyhow::bail!("denial assertion failed: {provider} / {error_kind} not found");
        }
    }
    Ok(())
}

fn validate_provider_results(
    results: &[ProviderCallResult],
    expected: &[DemoProviderCall],
) -> anyhow::Result<()> {
    anyhow::ensure!(
        results.len() == expected.len(),
        "agent result count {} does not match oracle count {}",
        results.len(),
        expected.len()
    );
    for (index, (actual, oracle)) in results.iter().zip(expected).enumerate() {
        anyhow::ensure!(
            actual.provider == oracle.provider
                && actual.action == oracle.action
                && actual.decision == oracle.decision
                && actual.execution_status == oracle.execution_status
                && actual.side_effect_executed == oracle.side_effect_executed
                && (oracle.error_kind.is_none() || actual.error_kind == oracle.error_kind),
            "agent step {} diverged from oracle: actual={}/{}/{}/{:?}, expected={}/{}/{}/{:?}",
            index + 1,
            actual.provider,
            actual.decision,
            actual.execution_status,
            actual.error_kind,
            oracle.provider,
            oracle.decision,
            oracle.execution_status,
            oracle.error_kind
        );
    }
    Ok(())
}

fn provider_is_external(provider: &str) -> bool {
    full_provider_registry()
        .get(provider)
        .is_some_and(|record| record.class == ProviderClass::External)
}

fn demo_egress_host(arguments: &Value) -> Option<String> {
    let url = arguments.get("url").and_then(Value::as_str)?;
    let authority = url.split_once("://")?.1.split('/').next()?;
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority)
        .trim_start_matches('[')
        .split([']', ':'])
        .next()?
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
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

fn call_external_provider(
    provider: &str,
    action: &str,
    arguments: &Value,
    sandbox_root: &Path,
) -> Value {
    let executed = tools::execute_external_tool(provider, action, arguments, sandbox_root);
    let execution_status = executed
        .get("execution_status")
        .and_then(Value::as_str)
        .unwrap_or("simulated");
    let simulated = executed
        .get("simulated")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let side_effect_executed = executed
        .get("side_effect_executed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    json!({
        "provider": provider,
        "decision": "allowed",
        "execution_status": execution_status,
        "simulated": simulated,
        "side_effect_executed": side_effect_executed,
        "output": executed.get("output").cloned().unwrap_or(Value::Null)
    })
}

#[derive(Debug, Clone, Deserialize, Serialize)]
// Note: execution path only reads provider/action/arguments; the remaining
// fields are used by validate_scenario_expectations to assert results match
// expected/*.json fixtures. serde ignores extras on the execution path.
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

/// The deterministic agent driver is deliberately separate from the expected
/// outcome oracle. It contains only the intent that is executed.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DemoAgentStep {
    provider: String,
    action: String,
    #[serde(default)]
    arguments: Value,
}

fn evaluate_scenario_corpora(root: &Path, suite: &Path) -> anyhow::Result<Value> {
    let suite_path = root.join(suite);
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
    match read_agent_script(&scenario_path.join("agent/script.json")) {
        Ok(agent_steps) => failures.extend(validate_scenario_story(
            scenario_path,
            &provider_calls,
            &agent_steps,
        )),
        Err(_) => failures.push("agent_script_is_unreadable".to_string()),
    }
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
        let simulated = call.execution_status == "simulated";
        let event_type = match (call.decision.as_str(), simulated) {
            ("allowed", true) => "provider_simulated_replay",
            ("allowed", false) => "provider_completed",
            ("requires_review", _) => "provider_approval_pending",
            ("denied", _) => "provider_denied",
            _ => "provider_failed",
        };
        store.append_signed(
            obs_id,
            event_type.to_string(),
            Some(call.provider.clone()),
            json!({
                "scenario": scenario,
                "provider": &call.provider,
                "action": &call.action,
                "decision": &call.decision,
                "execution_status": &call.execution_status,
                "reason": &call.reason,
                "error_kind": &call.error_kind,
                "arguments": &call.arguments,
                "side_effect_executed": call.side_effect_executed,
                "simulated": simulated
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
    let suite_path = root.join(suite);
    let eval = evaluate_scenario_corpora(root, suite)?;
    if eval["passed"].as_bool() != Some(true) {
        anyhow::bail!("scenario suite eval did not pass");
    }
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
        let provider_calls =
            read_demo_provider_calls(&scenario_path.join("expected/provider-calls.json"))?;
        let report = read_report(&scenario_path.join("expected/report.json"))?;
        markdown.push_str(&format!("## {}\n\n", scenario));
        markdown
            .push_str("| Provider | Defense | Decision | Status | Side Effect | Obs | Reason |\n");
        markdown.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
        for call in &provider_calls {
            let defense_layer = server::defense_layer_for(
                Some(&call.provider),
                Some(&call.decision),
                call.error_kind.as_deref(),
            );
            markdown.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                markdown_cell(&call.provider),
                defense_layer,
                markdown_cell(&call.decision),
                markdown_cell(&call.execution_status),
                call.side_effect_executed,
                markdown_cell(call.obs_ref.as_deref().unwrap_or("")),
                markdown_cell(call.reason.as_deref().unwrap_or(""))
            ));
        }
        markdown.push('\n');
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

fn ensure_contest_scenario(scenario: &str) -> anyhow::Result<()> {
    if CONTEST_SCENARIOS.contains(&scenario) {
        Ok(())
    } else {
        anyhow::bail!("unknown contest scenario: {scenario}");
    }
}

fn ensure_required_scenario_files(path: &Path) -> anyhow::Result<()> {
    let static_required = scenario_required_files();
    let mut missing = Vec::new();
    for relative in static_required {
        if !path.join(relative).exists() {
            missing.push(*relative);
        }
    }
    // The attacks/ directory must contain at least one .md file; the filename
    // is scenario-specific (e.g. path-escape.md, prompt-injection.md).
    let attacks_dir = path.join("attacks");
    let has_attack = attacks_dir.is_dir()
        && std::fs::read_dir(&attacks_dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .any(|e| e.path().extension().is_some_and(|ext| ext == "md"))
            })
            .unwrap_or(false);
    if !has_attack {
        missing.push("attacks/*.md");
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

fn read_agent_script(path: &Path) -> anyhow::Result<Vec<DemoAgentStep>> {
    let value = read_json_value(path)?;
    let steps = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("{} must contain a JSON array", path.display()))?;
    steps
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)
}

/// Validate that a deterministic contest replay is anchored to the adversarial
/// input and that the declared agent plan matches the calls we actually run.
/// This prevents a benign fixture from being presented as attack evidence.
fn validate_scenario_story(
    path: &Path,
    calls: &[DemoProviderCall],
    script: &[DemoAgentStep],
) -> Vec<String> {
    let mut failures = Vec::new();
    let Some(inspect) = calls.first() else {
        return vec!["attack_story_has_no_provider_calls".to_string()];
    };
    if inspect.provider != "runwarden.input.inspect" {
        failures.push("attack_story_must_start_with_input_inspection".to_string());
    }
    let attack_input = inspect
        .arguments
        .get("input_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if let Err(error) = resolve_attack_fixture(path, attack_input) {
        failures.push(format!(
            "input_inspection_is_not_bound_to_attack_fixture: {error}"
        ));
    }

    if script.len() != calls.len() {
        failures.push("agent_script_call_count_mismatch".to_string());
    }
    for (index, (step, call)) in script.iter().zip(calls).enumerate() {
        if step.provider != call.provider
            || step.action != call.action
            || step.arguments != call.arguments
        {
            failures.push(format!("agent_script_step_{}_mismatch", index + 1));
        }
    }
    failures
}

/// Resolve a scenario attack fixture without allowing absolute paths,
/// traversal components, or symlinks that escape the scenario's attacks/
/// directory. Returning the canonical path also makes the subsequent read use
/// the same confinement decision that validation made.
fn resolve_attack_fixture(scenario_path: &Path, input_path: &str) -> anyhow::Result<PathBuf> {
    let relative = Path::new(input_path);
    anyhow::ensure!(!input_path.trim().is_empty(), "attack input path is empty");
    anyhow::ensure!(
        !relative.is_absolute(),
        "attack input path must be relative"
    );
    anyhow::ensure!(
        relative
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "attack input path must not contain traversal or platform-root components"
    );
    anyhow::ensure!(
        relative.starts_with("attacks")
            && relative.extension().and_then(|ext| ext.to_str()) == Some("md"),
        "attack input path must name a Markdown file under attacks/"
    );

    let scenario_root = scenario_path
        .canonicalize()
        .map_err(|error| anyhow::anyhow!("canonicalize scenario directory: {error}"))?;
    let attacks_root = scenario_path
        .join("attacks")
        .canonicalize()
        .map_err(|error| anyhow::anyhow!("canonicalize attacks directory: {error}"))?;
    anyhow::ensure!(
        attacks_root.starts_with(&scenario_root),
        "scenario attacks/ directory resolves outside the scenario"
    );
    let candidate = scenario_path
        .join(relative)
        .canonicalize()
        .map_err(|error| anyhow::anyhow!("canonicalize attack input fixture: {error}"))?;
    anyhow::ensure!(candidate.is_file(), "attack input fixture is not a file");
    anyhow::ensure!(
        candidate.starts_with(&attacks_root),
        "attack input fixture resolves outside scenario attacks/"
    );
    Ok(candidate)
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
    if content.trim_start().starts_with('[') {
        Ok(serde_json::from_str(&content)?)
    } else {
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str::<TraceEvent>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)
    }
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

fn resolve_workspace_output_path(
    root: &Path,
    requested: &Path,
    label: &str,
) -> anyhow::Result<PathBuf> {
    resolve_workspace_relative_path(root, requested)
        .map_err(|_| anyhow::anyhow!("{label} path must be a relative path inside the workspace"))
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

fn run_strict_check(json_output: bool) -> anyhow::Result<()> {
    let root = find_workspace_root(env::current_dir()?)?;
    for path in [
        "Cargo.toml",
        "README.md",
        "docs/README.md",
        "docs/reference/cli.md",
        "docs/reference/mcp.md",
        "docs/reference/provider-model.md",
        "docs/reference/provider-integration.md",
        "docs/reference/evidence-and-accountability.md",
        "docs/reference/webui-review-console.md",
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
        "runwarden check --strict",
        "runwarden demo --all",
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

    if json_output {
        println!("{}", serde_json::to_string_pretty(&scenario_eval)?);
    } else {
        println!("runwarden strict check passed");
    }
    Ok(())
}

fn find_workspace_root(mut current: PathBuf) -> anyhow::Result<PathBuf> {
    loop {
        if current.join("Cargo.toml").exists()
            && current.join("docs/README.md").exists()
            && current.join("scenarios").is_dir()
        {
            return Ok(current);
        }
        if !current.pop() {
            anyhow::bail!("could not find workspace root (no Cargo.toml)");
        }
    }
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn markdown_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
mod main_tests {
    use super::*;

    #[test]
    fn proxy_listener_reservation_fails_when_port_is_already_owned() {
        let occupied = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                // Some hermetic test sandboxes forbid loopback sockets. The
                // same test exercises the real bind collision in normal CI.
                return;
            }
            Err(error) => panic!("occupy port: {error}"),
        };
        let port = occupied.local_addr().expect("occupied address").port();
        let token_env = "RUNWARDEN_PROXY_CLIENT_TOKEN_CLI_BIND_TEST";
        // SAFETY: this test uses a test-specific environment variable.
        unsafe {
            std::env::set_var(token_env, "0123456789abcdef0123456789abcdef");
        }
        let cli = runwarden_llm_proxy::Cli {
            bind: "127.0.0.1".to_string(),
            port,
            upstream: "http://127.0.0.1:1/v1".to_string(),
            api_key_env: "RUNWARDEN_LLM_API_KEY_CLI_BIND_TEST".to_string(),
            client_token_env: token_env.to_string(),
            trace: "/tmp/runwarden-cli-bind-test.jsonl".to_string(),
            max_body_bytes: 1024,
        };
        let error = runwarden_llm_proxy::bind_listener(&cli)
            .expect_err("occupied proxy port must fail before the console starts");
        assert!(error.to_string().contains("bind Runwarden LLM proxy"));
        unsafe {
            std::env::remove_var(token_env);
        }
    }

    #[test]
    fn generated_proxy_client_token_meets_proxy_entropy_contract() {
        let token = generate_proxy_client_token().expect("proxy token");
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(
            token
                .bytes()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                >= 8
        );
    }

    #[test]
    fn demo_agent_step_rejects_oracle_fields() {
        let error = serde_json::from_value::<DemoAgentStep>(json!({
            "provider": "runwarden.input.inspect",
            "action": "inspect",
            "arguments": {"input_path": "attacks/prompt-injection.md"},
            "decision": "allowed"
        }))
        .expect_err("driver must reject oracle-only fields");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn attack_fixture_rejects_absolute_and_parent_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let attacks = temp.path().join("attacks");
        fs::create_dir_all(&attacks).expect("attacks dir");
        fs::write(attacks.join("attack.md"), "attack").expect("attack fixture");

        assert!(resolve_attack_fixture(temp.path(), "/etc/passwd").is_err());
        assert!(resolve_attack_fixture(temp.path(), "attacks/../outside.md").is_err());
        assert!(resolve_attack_fixture(temp.path(), "../attacks/attack.md").is_err());
        assert_eq!(
            resolve_attack_fixture(temp.path(), "attacks/attack.md").expect("valid fixture"),
            attacks.join("attack.md").canonicalize().expect("canonical")
        );
    }

    #[cfg(unix)]
    #[test]
    fn attack_fixture_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let attacks = temp.path().join("scenario/attacks");
        fs::create_dir_all(&attacks).expect("attacks dir");
        let outside = temp.path().join("outside.md");
        fs::write(&outside, "outside").expect("outside fixture");
        symlink(&outside, attacks.join("escape.md")).expect("escape symlink");

        let error = resolve_attack_fixture(&temp.path().join("scenario"), "attacks/escape.md")
            .expect_err("symlink escape must fail");
        assert!(error.to_string().contains("outside scenario attacks"));
    }
}
