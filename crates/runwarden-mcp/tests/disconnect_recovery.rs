mod common;

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::{INSTANCE_TOKEN, McpFixture, payload};
use runwarden_kernel::authority::ApprovalState;
use runwarden_kernel::operation::{OperationState, ProviderExecutionStatus, SideEffectState};
use runwarden_kernel::story::OperationId;
use serde_json::{Value, json};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

#[test]
fn pending_email_survives_disconnect_and_resumes_once_in_a_fresh_process() {
    let fixture = McpFixture::new();

    let mut first_client = ProductionMcp::spawn(&fixture);
    let pending = first_client.call(
        1,
        "runwarden.provider.call",
        json!({
            "provider": "external.email.send",
            "to": ["judge@example.test"],
            "subject": "survive the MCP disconnect",
            "body": "execute this approved operation exactly once"
        }),
    );
    assert_eq!(pending["result"]["isError"], true);
    assert_eq!(payload(&pending)["disposition"], "awaiting_approval");
    let operation_id: OperationId =
        serde_json::from_value(payload(&pending)["operation_id"].clone())
            .expect("pending operation id");

    // Model a real client disconnect: close the first process's stdin and wait
    // for the production stdio server to observe EOF and exit.
    first_client.disconnect();
    fixture.approve(operation_id);

    let mut reconnected_client = ProductionMcp::spawn(&fixture);
    let resumed = reconnected_client.call(
        2,
        "runwarden.operation.resume",
        json!({"operation_id": operation_id}),
    );
    assert_completed_snapshot(&resumed, operation_id);
    let receipt_path = fixture
        .sandbox_root
        .join("mail/receipts")
        .join(format!("{operation_id}.json"));
    let receipt_after_completion = fs::read(&receipt_path).expect("completed email receipt");
    let events_after_completion = fixture
        .store
        .events_after(fixture.story.story_id, 0, 256)
        .expect("events after first completion");

    let status = reconnected_client.call(
        3,
        "runwarden.operation.status",
        json!({"operation_id": operation_id}),
    );
    assert_completed_snapshot(&status, operation_id);

    // A resume of the terminal operation must return its unchanged durable
    // snapshot; the receipt assertion below independently guards the external
    // one-shot effect.
    let terminal_resume = reconnected_client.call(
        4,
        "runwarden.operation.resume",
        json!({"operation_id": operation_id}),
    );
    assert_completed_snapshot(&terminal_resume, operation_id);
    assert_eq!(
        payload(&terminal_resume),
        payload(&status),
        "terminal resume must return the unchanged durable snapshot"
    );
    assert_eq!(
        fixture
            .store
            .events_after(fixture.story.story_id, 0, 256)
            .expect("events after terminal resume"),
        events_after_completion,
        "status and terminal resume must not append execution evidence"
    );
    assert_eq!(
        fs::read(&receipt_path).expect("receipt after terminal resume"),
        receipt_after_completion,
        "terminal resume must not rewrite the provider receipt"
    );
    reconnected_client.disconnect();

    let operation = fixture
        .store
        .operation(operation_id)
        .expect("durable completed operation");
    assert_eq!(operation.state, OperationState::Completed);
    assert_eq!(operation.side_effect_state, SideEffectState::Completed);
    assert_eq!(
        operation
            .provider_result
            .as_ref()
            .expect("completed provider result")
            .execution_status,
        ProviderExecutionStatus::Completed
    );
    let approval = fixture
        .store
        .approval_for_operation(operation_id)
        .expect("durable approval lookup")
        .expect("approval for completed email operation");
    assert_eq!(approval.state, ApprovalState::Consumed);

    let receipt_dir = fixture.sandbox_root.join("mail/receipts");
    let mut receipt_files = fs::read_dir(&receipt_dir)
        .expect("email receipt directory")
        .map(|entry| entry.expect("receipt directory entry").path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    receipt_files.sort();
    assert_eq!(
        receipt_files.len(),
        1,
        "disconnect recovery must create one immutable email receipt"
    );
    let expected_receipt_name = format!("{operation_id}.json");
    assert_eq!(
        receipt_files[0].file_name().and_then(|name| name.to_str()),
        Some(expected_receipt_name.as_str())
    );
}

fn assert_completed_snapshot(response: &Value, operation_id: OperationId) {
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(payload(response)["disposition"], "completed");
    assert_eq!(payload(response)["operation_state"], "completed");
    assert_eq!(
        payload(response)["operation_id"],
        Value::String(operation_id.to_string())
    );
}

struct ProductionMcp {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    responses: Receiver<io::Result<String>>,
    stdout_reader: Option<JoinHandle<()>>,
}

impl ProductionMcp {
    fn spawn(fixture: &McpFixture) -> Self {
        let mut child = production_command(fixture)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn production runwarden-mcp");
        let stdin = child.stdin.take().expect("production MCP stdin");
        let stdout = child.stdout.take().expect("production MCP stdout");
        let (send, responses) = mpsc::channel();
        let stdout_reader = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                match stdout.read_line(&mut line) {
                    Ok(0) => return,
                    Ok(_) => {
                        if send.send(Ok(line)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = send.send(Err(error));
                        return;
                    }
                }
            }
        });
        Self {
            child: Some(child),
            stdin: Some(stdin),
            responses,
            stdout_reader: Some(stdout_reader),
        }
    }

    fn call(&mut self, id: i64, name: &str, arguments: Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments}
        });
        let stdin = self.stdin.as_mut().expect("live production MCP stdin");
        serde_json::to_writer(&mut *stdin, &request).expect("write MCP request");
        stdin.write_all(b"\n").expect("terminate NDJSON request");
        stdin.flush().expect("flush MCP request");

        let line = match self.responses.recv_timeout(RESPONSE_TIMEOUT) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => panic!("failed reading production MCP response: {error}"),
            Err(RecvTimeoutError::Timeout) => {
                panic!("production MCP response exceeded {RESPONSE_TIMEOUT:?}")
            }
            Err(RecvTimeoutError::Disconnected) => {
                let status = self
                    .child
                    .as_mut()
                    .and_then(|child| child.try_wait().ok())
                    .flatten();
                panic!("production MCP closed stdout before responding; status={status:?}")
            }
        };
        let response: Value = serde_json::from_str(&line).expect("production MCP JSON response");
        assert_eq!(response["id"], id, "response must match request id");
        response
    }

    fn disconnect(mut self) {
        let status = self
            .shutdown()
            .unwrap_or_else(|error| panic!("production MCP disconnect failed: {error}"));
        assert!(
            status.success(),
            "production MCP did not exit cleanly after stdin EOF: {status}"
        );
    }

    fn shutdown(&mut self) -> Result<ExitStatus, String> {
        self.stdin.take();
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        loop {
            let status = match self
                .child
                .as_mut()
                .expect("production MCP child")
                .try_wait()
            {
                Ok(status) => status,
                Err(error) => {
                    self.kill_and_reap();
                    return Err(format!(
                        "could not poll child: {error}; process killed and reaped"
                    ));
                }
            };
            if let Some(status) = status {
                self.child.take();
                self.join_stdout_reader();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                self.kill_and_reap();
                return Err(format!(
                    "process did not exit within {SHUTDOWN_TIMEOUT:?}; killed and reaped"
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn kill_and_reap(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.join_stdout_reader();
    }

    fn join_stdout_reader(&mut self) {
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for ProductionMcp {
    fn drop(&mut self) {
        if self.child.is_some() {
            let _ = self.shutdown();
        }
    }
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
