import { describe, expect, it } from "vitest";
import { RunwardenClient, type FetchInit, type ProviderOutcome } from "./index";

describe("RunwardenClient", () => {
  it("advertises the agent-native security kernel boundary", async () => {
    const client = new RunwardenClient("http://127.0.0.1:8088/");

    await expect(client.agentBootstrap()).resolves.toMatchObject({
      architecture: "agent_native_security_kernel",
      agent_only_sees_runwarden: true,
      raw_side_effect_tools_allowed: false
    });
  });

  it("keeps policy decision separate from execution status in TS contracts", () => {
    const outcome: ProviderOutcome = {
      decision: "denied",
      execution_status: "not_executed",
      output: null,
      envelope: {
        decision: "denied",
        gate_id: "provider_allowlist",
        error_kind: "provider_not_allowed",
        denied_by: "kernel",
        reason: "provider is not allowed for this session",
        provider: "external.shell.command",
        action: "run",
        target: "",
        execution_mode: "enforced",
        side_effect_executed: false
      },
      observation_id: "obs_1",
      artifacts: [],
      next_actions: []
    };

    expect(outcome.decision).toBe("denied");
    expect(outcome.execution_status).toBe("not_executed");
    expect(outcome.envelope.error_kind).toBe("provider_not_allowed");
  });

  it("loads approval queue through the Local API with the launch token", async () => {
    const calls: Array<{ url: string; init: FetchInit | undefined }> = [];
    const client = new RunwardenClient("http://127.0.0.1:8088/", {
      launchToken: "launch-secret",
      fetch: async (url, init) => {
        calls.push({ url, init });
        return {
          ok: true,
          status: 200,
          json: async () => ({
            approvals: [{ approval_id: "approval-1", state: "pending" }],
            side_effect_executed: false
          })
        };
      }
    });

    const queue = await client.approvalQueue();

    expect(queue.approvals).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      url: "http://127.0.0.1:8088/approvals",
      init: {
        headers: {
          authorization: "Bearer launch-secret"
        }
      }
    });
  });

  it("rejects launch tokens for non-local base URLs by default", () => {
    expect(
      () =>
        new RunwardenClient("https://evil.example/", {
          launchToken: "launch-secret"
        })
    ).toThrow("launchToken may only be used with local Runwarden API origins");
  });

  it("sends an Origin header for Node and agent fetch clients", async () => {
    const calls: Array<{ url: string; init: FetchInit | undefined }> = [];
    const client = new RunwardenClient("http://127.0.0.1:8088/", {
      launchToken: "launch-secret",
      fetch: async (url, init) => {
        calls.push({ url, init });
        return {
          ok: true,
          status: 200,
          json: async () => ({ providers: [], side_effect_executed: false })
        };
      }
    });

    await client.providerList();

    expect(calls[0]!.init?.headers).toMatchObject({
      authorization: "Bearer launch-secret",
      origin: "http://127.0.0.1:8088"
    });
  });

  it("submits approval decisions to the Local API without local state changes", async () => {
    const calls: Array<{ url: string; init: FetchInit | undefined }> = [];
    const client = new RunwardenClient("http://127.0.0.1:8088/", {
      launchToken: "launch-secret",
      fetch: async (url, init) => {
        calls.push({ url, init });
        return {
          ok: true,
          status: 200,
          json: async () => ({
            approval: {
              approval_id: "approval-1",
              state: "approved",
              reviewer: "reviewer-alice",
              reason: "reviewed exact command"
            },
            side_effect_executed: true
          })
        };
      }
    });

    const result = await client.approveApproval("approval-1", {
      reviewer: "reviewer-alice",
      reason: "reviewed exact command"
    });

    expect(result.approval.state).toBe("approved");
    expect(calls[0]).toMatchObject({
      url: "http://127.0.0.1:8088/approvals/approval-1/approve",
      init: {
        method: "POST",
        body: JSON.stringify({
          reviewer: "reviewer-alice",
          reason: "reviewed exact command"
        })
      }
    });
  });

  it("routes core interaction methods through the Local API", async () => {
    const calls: Array<{ url: string; init: FetchInit | undefined }> = [];
    const client = new RunwardenClient("http://127.0.0.1:8088/", {
      launchToken: "launch-secret",
      fetch: async (url, init) => {
        calls.push({ url, init });
        return {
          ok: true,
          status: 200,
          json: async () => ({ ok: true, url })
        };
      }
    });

    await client.sessionCreateFromManifest({ session_id: "session-1", manifest_toml: "version = \"1\"" });
    await client.providerList("session-1");
    await client.providerStatus("runwarden.report.render");
    await client.providerCall({
      session_id: "session-1",
      provider: "runwarden.input.inspect",
      action: "inspect",
      arguments: { input_text: "hello" }
    });
    await client.traceExport({ trace_path: "trace.json" });
    await client.reportLint({ report_path: "report.json", trace_path: "trace.json" });
    await client.reportRender({ report_path: "report.json", trace_path: "trace.json", format: "html" });
    await client.artifactVerify({ artifacts_path: "artifacts", manifest_path: "artifact-manifest.json" });
    await client.artifactSubmission({ full: true, output_path: "artifacts" });
    await client.evalAgentNative();
    await client.releaseSmoke();
    await client.uiLaunch({ bind: "127.0.0.1", port: 8088, artifacts_path: "artifacts" });
    await client.agentCheckConfig({ client: "claude", input_path: "claude.json" });

    expect(calls.map((call) => new URL(call.url).pathname)).toEqual([
      "/sessions",
      "/providers",
      "/providers/runwarden.report.render/status",
      "/provider-calls",
      "/trace/export",
      "/reports/lint",
      "/reports/render",
      "/artifacts/verify",
      "/artifacts/submission",
      "/eval/agent-native",
      "/release/smoke",
      "/ui/launch",
      "/agent/config/check"
    ]);
    expect(calls[0]!.init).toMatchObject({
      method: "POST",
      headers: {
        authorization: "Bearer launch-secret",
        "content-type": "application/json"
      }
    });
  });
});
