mod common;

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::{INSTANCE_TOKEN, McpFixture, call, payload};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::operation::{
    OperationState, ProviderExecutionStatus, SafeProviderOutput, SideEffectState,
};
use runwarden_kernel::story::OperationId;
use runwarden_kernel::trace::{Sha256Digest, StoryEvent, StoryEventPayload};
use serde_json::{Value, json};

const PROCESS_TIMEOUT: Duration = Duration::from_secs(20);

#[test]
fn two_mcp_processes_resume_one_approved_email_at_most_once() {
    let fixture = McpFixture::new();
    let pending = call(
        &fixture.server,
        80,
        "runwarden.provider.call",
        json!({
            "provider": "external.email.send",
            "to": ["judge@example.test"],
            "subject": "cross-process approval",
            "body": "execute this approved operation once"
        }),
    );
    assert_eq!(pending["result"]["isError"], true);
    assert_eq!(payload(&pending)["disposition"], "awaiting_approval");
    let operation_id: OperationId =
        serde_json::from_value(payload(&pending)["operation_id"].clone())
            .expect("pending operation id");
    fixture.approve(operation_id);

    // Resume carries only the durable id. Both real MCP processes load the
    // frozen provider arguments from the shared journal after winning its CAS.
    let resume_arguments = json!({"operation_id": operation_id});
    assert_eq!(resume_arguments.as_object().unwrap().len(), 1);
    let request = json!({
        "jsonrpc": "2.0",
        "id": 81,
        "method": "tools/call",
        "params": {
            "name": "runwarden.operation.resume",
            "arguments": resume_arguments
        }
    })
    .to_string();

    let responses = concurrent_resumes(&fixture, &request)
        .unwrap_or_else(|error| panic!("concurrent MCP resume failed: {error}"));
    assert_eq!(responses.len(), 2);

    let completed_responses = responses
        .iter()
        .filter(|response| is_completed_response(response, operation_id))
        .count();
    assert!(
        completed_responses >= 1,
        "at least one process must observe completion: {responses:#?}"
    );
    for response in &responses {
        assert!(
            is_completed_response(response, operation_id)
                || is_operation_conflict(response, operation_id)
                || is_executing_snapshot(response, operation_id),
            "each process must observe completion, lease conflict, or the CAS winner in progress: {response:#?}"
        );
    }
    let final_status = call(
        &fixture.server,
        82,
        "runwarden.operation.status",
        json!({"operation_id": operation_id}),
    );
    assert!(
        is_completed_response(&final_status, operation_id),
        "the durable status must converge to completed: {final_status:#?}"
    );

    let operation = fixture.store.operation(operation_id).unwrap();
    assert_eq!(operation.state, OperationState::Completed);
    assert_eq!(operation.side_effect_state, SideEffectState::Completed);
    let provider_result = operation
        .provider_result
        .as_ref()
        .expect("completed email provider result");
    assert_eq!(
        provider_result.execution_status,
        ProviderExecutionStatus::Completed
    );
    let provider_receipt_hash = match &provider_result.output {
        SafeProviderOutput::Email { receipt_hash } => receipt_hash,
        other => panic!("completed email operation returned {other:?}"),
    };
    let approval = fixture
        .store
        .approval_for_operation(operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(approval.state, ApprovalState::Consumed);
    let budget = fixture
        .store
        .budget_snapshot(fixture.story.authority.session_id)
        .expect("durable budget snapshot");
    assert_eq!(budget.calls_reserved, 0);
    assert_eq!(budget.calls_committed, 1);

    let events = fixture
        .store
        .events_after(fixture.story.story_id, 0, 256)
        .unwrap();
    assert_eq!(
        provider_event_count(
            &events,
            operation_id,
            "provider_execution_started",
            SideEffectState::NotAttempted,
        ),
        1,
        "SQLite execution-start CAS must have exactly one winner"
    );
    assert_eq!(
        provider_event_count(
            &events,
            operation_id,
            "completed",
            SideEffectState::Completed,
        ),
        1,
        "the winning execution must commit exactly one completed result"
    );
    let (completed_obs, event_receipt_hash) = events
        .iter()
        .find_map(|event| match event.payload() {
            StoryEventPayload::ProviderExecution {
                execution_status,
                side_effect_state: SideEffectState::Completed,
                receipt_hash: Some(receipt_hash),
                ..
            } if event.operation_id == Some(operation_id)
                && execution_status.as_str() == "completed" =>
            {
                Some((event.obs_id, receipt_hash))
            }
            _ => None,
        })
        .expect("one completed email event with receipt hash");
    let started_obs = events
        .iter()
        .find_map(|event| match event.payload() {
            StoryEventPayload::ProviderExecution {
                execution_status,
                side_effect_state: SideEffectState::NotAttempted,
                ..
            } if event.operation_id == Some(operation_id)
                && execution_status.as_str() == "provider_execution_started" =>
            {
                Some(event.obs_id)
            }
            _ => None,
        })
        .expect("one provider execution-start event");
    assert!(operation.observation_refs.contains(&started_obs));
    assert!(operation.observation_refs.contains(&completed_obs));
    assert_eq!(event_receipt_hash, provider_receipt_hash);

    let receipt_directory = fixture.sandbox_root.join("mail/receipts");
    let receipts = fs::read_dir(&receipt_directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", receipt_directory.display()))
        .collect::<Result<Vec<_>, _>>()
        .expect("read receipt entries");
    assert_eq!(receipts.len(), 1, "email side effect must have one receipt");
    assert_eq!(
        receipts[0].path(),
        receipt_directory.join(format!("{operation_id}.json")),
        "the sole receipt must be bound to the resumed operation"
    );
    let receipt_bytes = fs::read(receipts[0].path()).expect("read immutable email receipt");
    assert_eq!(
        &Sha256Digest::from_bytes(&receipt_bytes),
        provider_receipt_hash,
        "provider result and durable receipt bytes must have the same hash"
    );
}

fn is_completed_response(response: &Value, operation_id: OperationId) -> bool {
    response["result"]["isError"] == false
        && response["result"]["structuredContent"]["operation_id"] == operation_id.to_string()
        && response["result"]["structuredContent"]["disposition"] == "completed"
        && response["result"]["structuredContent"]["operation_state"] == "completed"
        && response["result"]["structuredContent"]["side_effect_state"] == "completed"
        && response["result"]["structuredContent"]["provider_result"]["execution_status"]
            == "completed"
}

fn is_operation_conflict(response: &Value, operation_id: OperationId) -> bool {
    response["result"]["isError"] == true
        && response["result"]["structuredContent"]["operation_id"] == operation_id.to_string()
        && response["result"]["structuredContent"]["error_kind"] == "operation_conflict"
        && response["result"]["structuredContent"]["reason_code"] == "operation_conflict"
        && response["result"]["structuredContent"]["side_effect_executed"] == false
}

fn is_executing_snapshot(response: &Value, operation_id: OperationId) -> bool {
    let payload = &response["result"]["structuredContent"];
    response["result"]["isError"] == false
        && payload["operation_id"] == operation_id.to_string()
        && payload["disposition"] == "executing"
        && ((payload["operation_state"] == "executing"
            && payload["approval"]["state"] == "consumed")
            || (payload["operation_state"] == "execution_leased"
                && payload["approval"]["state"] == "leased"))
        && payload["side_effect_state"] == "not_attempted"
        && payload["provider_result"].is_null()
}

fn provider_event_count(
    events: &[StoryEvent],
    operation_id: OperationId,
    expected_status: &str,
    expected_side_effect: SideEffectState,
) -> usize {
    events
        .iter()
        .filter(|event| {
            if event.operation_id != Some(operation_id) {
                return false;
            }
            matches!(
                event.payload(),
                StoryEventPayload::ProviderExecution {
                    execution_status,
                    side_effect_state,
                    ..
                } if execution_status.as_str() == expected_status
                    && *side_effect_state == expected_side_effect
            )
        })
        .count()
}

enum WorkerEvent {
    Ready(usize),
    Finished(usize, Result<Value, String>),
}

fn concurrent_resumes(fixture: &McpFixture, request: &str) -> Result<Vec<Value>, String> {
    let gate = Arc::new(StartGate::default());
    let _open_gate_on_return = OpenGateOnDrop(Arc::clone(&gate));
    let (event_tx, event_rx) = mpsc::channel();
    let mut children = Vec::with_capacity(2);
    let mut workers = Vec::with_capacity(2);

    for index in 0..2 {
        let mut child = production_command(fixture)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| format!("spawn MCP process {index}: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("MCP process {index} has no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("MCP process {index} has no stdout"))?;
        children.push(ChildGuard::new(child));

        let worker_gate = Arc::clone(&gate);
        let worker_events = event_tx.clone();
        let worker_request = request.to_owned();
        let worker = thread::Builder::new()
            .name(format!("mcp-resume-{index}"))
            .spawn(move || {
                process_worker(
                    index,
                    stdin,
                    stdout,
                    worker_gate,
                    worker_events,
                    worker_request,
                );
            })
            .map_err(|error| format!("spawn MCP I/O worker {index}: {error}"))?;
        workers.push(worker);
    }
    drop(event_tx);

    let deadline = Instant::now() + PROCESS_TIMEOUT;
    let result = collect_concurrent_responses(&event_rx, &gate, deadline);

    // Open the gate even on readiness failure, then terminate every child to
    // interrupt any outstanding pipe read before joining the I/O workers.
    gate.open();
    for child in &mut children {
        child.terminate();
    }
    for worker in workers {
        if worker.join().is_err() && result.is_ok() {
            return Err("an MCP I/O worker panicked".to_owned());
        }
    }
    result
}

fn collect_concurrent_responses(
    events: &Receiver<WorkerEvent>,
    gate: &StartGate,
    deadline: Instant,
) -> Result<Vec<Value>, String> {
    let mut ready = [false; 2];
    while ready.iter().any(|value| !value) {
        match receive_before(events, deadline)? {
            WorkerEvent::Ready(index) => ready[index] = true,
            WorkerEvent::Finished(index, result) => {
                return Err(match result {
                    Ok(response) => format!(
                        "MCP process {index} returned before the resume barrier: {response}"
                    ),
                    Err(error) => format!("MCP process {index} failed before the barrier: {error}"),
                });
            }
        }
    }

    // Both binaries have completed initialize and are blocked here, so this
    // single notify is the cross-process resume barrier.
    gate.open();

    let mut responses = vec![None, None];
    while responses.iter().any(Option::is_none) {
        match receive_before(events, deadline)? {
            WorkerEvent::Ready(index) => {
                return Err(format!("MCP process {index} reported readiness twice"));
            }
            WorkerEvent::Finished(index, result) => {
                if responses[index].is_some() {
                    return Err(format!("MCP process {index} returned twice"));
                }
                responses[index] = Some(result?);
            }
        }
    }
    Ok(responses.into_iter().map(Option::unwrap).collect())
}

fn receive_before(
    events: &Receiver<WorkerEvent>,
    deadline: Instant,
) -> Result<WorkerEvent, String> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| "timed out waiting for MCP processes".to_owned())?;
    match events.recv_timeout(remaining) {
        Ok(event) => Ok(event),
        Err(RecvTimeoutError::Timeout) => Err("timed out waiting for MCP processes".to_owned()),
        Err(RecvTimeoutError::Disconnected) => {
            Err("all MCP I/O workers exited before returning responses".to_owned())
        }
    }
}

fn process_worker(
    index: usize,
    mut stdin: ChildStdin,
    stdout: ChildStdout,
    gate: Arc<StartGate>,
    events: Sender<WorkerEvent>,
    request: String,
) {
    let mut stdout = BufReader::new(stdout);
    let result = (|| {
        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 100 + index,
            "method": "initialize",
            "params": {}
        })
        .to_string();
        write_ndjson(&mut stdin, &initialize)?;
        let initialized = read_ndjson(&mut stdout)?;
        if initialized["result"].is_null() || initialized["id"] != 100 + index {
            return Err(format!("invalid initialize response: {initialized}"));
        }

        events
            .send(WorkerEvent::Ready(index))
            .map_err(|_| "test coordinator dropped before readiness".to_owned())?;
        gate.wait();

        write_ndjson(&mut stdin, &request)?;
        read_ndjson(&mut stdout)
    })();
    let _ = events.send(WorkerEvent::Finished(index, result));
}

fn write_ndjson(stdin: &mut ChildStdin, body: &str) -> Result<(), String> {
    stdin
        .write_all(body.as_bytes())
        .and_then(|_| stdin.write_all(b"\n"))
        .and_then(|_| stdin.flush())
        .map_err(|error| format!("write MCP request: {error}"))
}

fn read_ndjson(stdout: &mut BufReader<ChildStdout>) -> Result<Value, String> {
    let mut line = String::new();
    let bytes = stdout
        .read_line(&mut line)
        .map_err(|error| format!("read MCP response: {error}"))?;
    if bytes == 0 {
        return Err("MCP process closed stdout before responding".to_owned());
    }
    serde_json::from_str(&line).map_err(|error| format!("parse MCP response: {error}: {line:?}"))
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

#[derive(Default)]
struct StartGate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl StartGate {
    fn wait(&self) {
        let mut open = self.open.lock().unwrap_or_else(|error| error.into_inner());
        while !*open {
            open = self
                .changed
                .wait(open)
                .unwrap_or_else(|error| error.into_inner());
        }
    }

    fn open(&self) {
        let mut open = self.open.lock().unwrap_or_else(|error| error.into_inner());
        *open = true;
        self.changed.notify_all();
    }
}

struct OpenGateOnDrop(Arc<StartGate>);

impl Drop for OpenGateOnDrop {
    fn drop(&mut self) {
        // Setup failures must not leave an already-ready worker parked at the
        // start barrier after its child process has been reaped.
        self.0.open();
    }
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}
