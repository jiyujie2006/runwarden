import { describe, expect, it } from "vitest";
import {
  createDemoReviewerConsoleViewModel,
  renderDemoReviewerConsoleHtml,
  type DemoScenarioInput
} from "./index";

const demoInput: DemoScenarioInput = {
  scenario: "prompt-injection-file-exfil",
  provider_calls: [
    {
      provider: "runwarden.input.inspect",
      action: "inspect",
      decision: "allowed",
      execution_status: "completed",
      side_effect_executed: false,
      obs_ref: "obs_prompt_file_inspect"
    },
    {
      provider: "external.mcp.filesystem.read_file",
      action: "read_file",
      decision: "requires_review",
      execution_status: "not_executed",
      side_effect_executed: false,
      obs_ref: "obs_prompt_file_read_review"
    },
    {
      provider: "external.api.request",
      action: "request",
      decision: "denied",
      execution_status: "not_executed",
      side_effect_executed: false,
      obs_ref: "obs_prompt_file_exfil_denied"
    }
  ],
  denials: [
    {
      provider: "external.api.request",
      action: "request",
      decision: "denied",
      execution_status: "not_executed",
      side_effect_executed: false,
      obs_ref: "obs_prompt_file_exfil_denied"
    }
  ],
  metrics: {
    trace_completeness: 1,
    report_citation_accuracy: 1
  },
  report: {
    claims: [
      {
        id: "file-exfil-1",
        text: "The external API exfiltration request was denied before side effects.",
        obs_refs: ["obs_prompt_file_exfil_denied"]
      }
    ]
  },
  trace: [{ obs_id: "obs_prompt_file_exfil_denied" }],
  trace_verification: { verified: true },
  lint: { ok: true }
};

describe("createDemoReviewerConsoleViewModel", () => {
  it("summarizes attack denials review states trace and report evidence", () => {
    const model = createDemoReviewerConsoleViewModel([demoInput]);

    expect(model.suite).toMatchObject({
      scenarioCount: 1,
      denialCount: 1,
      reviewCount: 1,
      blockedSideEffectCount: 2,
      traceState: "verified"
    });
    expect(model.scenarios[0]).toMatchObject({
      scenario: "prompt-injection-file-exfil",
      providerCallCount: 3,
      denialCount: 1,
      reviewCount: 1,
      reportClaimCount: 1
    });
    expect(model.scenarios[0]?.reportObsRefs).toEqual(["obs_prompt_file_exfil_denied"]);
  });

  it("does not infer verified trace state from trace presence or lint success", () => {
    const { trace_verification: _traceVerification, ...inputWithoutVerification } = demoInput;
    const model = createDemoReviewerConsoleViewModel([inputWithoutVerification]);

    expect(model.suite.traceState).toBe("missing");
    expect(model.scenarios[0]?.traceState).toBe("missing");
  });

  it("does not mark an empty suite as verified", () => {
    const model = createDemoReviewerConsoleViewModel([]);

    expect(model.suite.traceState).toBe("missing");
  });
});

describe("renderDemoReviewerConsoleHtml", () => {
  it("renders static demo HTML without control-plane calls or script execution", () => {
    const html = renderDemoReviewerConsoleHtml([demoInput]);

    expect(html).toContain("Contest Reviewer Console");
    expect(html).toContain("prompt-injection-file-exfil");
    expect(html).toContain("Denials");
    expect(html).toContain("Requires review");
    expect(html).toContain("obs_prompt_file_exfil_denied");
    expect(html).toContain('role="status" aria-label="Demo suite status"');
    expect(html).toContain('aria-label="Runwarden demo scenarios"');
    expect(html).toContain("@media (max-width: 900px)");
    expect(html).toContain("min-height: 44px");
    expect(html).not.toContain("<script");
    expect(html).not.toContain("local_api");
    expect(html).not.toContain("approval-decision-form");
  });
});
