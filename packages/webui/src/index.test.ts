import { describe, expect, it } from "vitest";
import {
  buildApprovalQueueRows,
  buildApprovalDetails,
  createReviewerConsoleViewModel,
  createTraceExplorerStreamModel,
  renderReviewerConsoleHtml,
  reviewerAccessibilityContract,
  reviewerConsoleLayout
} from "./index";

describe("reviewerConsoleLayout", () => {
  it("uses the approved security workbench structure", () => {
    expect(reviewerConsoleLayout.shell).toBe("security-workbench");
    expect(reviewerConsoleLayout.regions).toEqual([
      "left-nav",
      "command-bar",
      "top-status-strip",
      "workbench-main",
      "details-drawer"
    ]);
    expect(reviewerConsoleLayout.approvalPolicy).toBe(
      "high-risk-actions-confirm-in-details-drawer"
    );
  });
});

describe("createReviewerConsoleViewModel", () => {
  it("prioritizes risk, trace integrity, approvals, and gates in the top strip", () => {
    const viewModel = createReviewerConsoleViewModel({
      sessionId: "session-1",
      riskStatus: "requires_review",
      traceIntegrity: "verified",
      pendingApprovalCount: 2,
      fastGateStatus: "passed",
      fullGateStatus: "missing"
    });

    expect(viewModel.statusStrip.map((item) => item.id)).toEqual([
      "session",
      "risk",
      "trace_integrity",
      "pending_approvals",
      "fast_gate",
      "full_gate"
    ]);
    expect(viewModel.statusStrip[1]).toMatchObject({
      label: "Risk",
      tone: "review"
    });
  });

  it("uses honest empty states without fake counts", () => {
    const viewModel = createReviewerConsoleViewModel({});

    expect(viewModel.modules.approvals.emptyState).toBe("No actions waiting for review");
    expect(viewModel.modules.agentBoundary.emptyState).toBe("No agent config checked");
    expect(viewModel.modules.providers.emptyState).toBe("No providers allowed for this session");
    expect(viewModel.modules.trace.emptyState).toBe("No trace events yet");
    expect(viewModel.modules.accountability.emptyState).toBe(
      "No accountability chain reconstructed"
    );
    expect(viewModel.modules.assurance.emptyState).toBe("No eval run yet");
    expect(viewModel.modules.settings.emptyState).toBe("No local settings changed");
    expect(viewModel.modules.approvals.count).toBeNull();
  });

  it("models loading error success and partial states for every workbench module", () => {
    const viewModel = createReviewerConsoleViewModel({
      moduleStates: {
        agentBoundary: { state: "success", count: 1 },
        providers: { state: "partial", count: 12, message: "Showing allowlisted providers" },
        approvals: { state: "loading" },
        trace: { state: "error", message: "Trace verification failed", sideEffectExecuted: false },
        accountability: { state: "success", message: "requester -> agent -> reviewer" },
        reports: { state: "empty" },
        artifacts: { state: "success", count: 6 },
        assurance: { state: "partial", message: "Fast gate passed, full gate missing" }
      }
    });

    expect(viewModel.modules.agentBoundary.state).toBe("success");
    expect(viewModel.modules.providers.state).toBe("partial");
    expect(viewModel.modules.approvals.state).toBe("loading");
    expect(viewModel.modules.trace.state).toBe("error");
    expect(viewModel.modules.trace.errorIncludesSideEffectState).toBe(true);
    expect(viewModel.modules.trace.sideEffectExecuted).toBe(false);
    expect(viewModel.modules.accountability.message).toBe("requester -> agent -> reviewer");
    expect(viewModel.modules.assurance.message).toBe("Fast gate passed, full gate missing");
  });
});

describe("reviewerAccessibilityContract", () => {
  it("keeps keyboard focus and touch targets explicit for approval actions", () => {
    expect(reviewerAccessibilityContract.minTouchTargetPx).toBeGreaterThanOrEqual(44);
    expect(reviewerAccessibilityContract.keyboardFlows).toContain("details-drawer");
    expect(reviewerAccessibilityContract.focusOrder).toEqual([
      "left-nav",
      "command-bar",
      "top-status-strip",
      "module-tabs",
      "approval-row",
      "details-drawer",
      "decision-actions"
    ]);
    expect(reviewerAccessibilityContract.contrast).toBe("AA");
  });
});

describe("createTraceExplorerStreamModel", () => {
  it("represents paged trace export state without fake completeness", () => {
    const model = createTraceExplorerStreamModel({
      verified: true,
      exportedEventCount: 50,
      totalMatching: 125,
      nextOffset: 50,
      truncatedByBytes: false
    });

    expect(model.state).toBe("partial");
    expect(model.progressLabel).toBe("50 / 125 events");
    expect(model.nextAction).toBe("load_more");
    expect(model.sideEffectExecuted).toBe(false);
  });
});

describe("buildApprovalDetails", () => {
  it("requires visible context and reviewer reason for high-risk approvals", () => {
    const details = buildApprovalDetails({
      provider: "runwarden.report.render",
      action: "render",
      risk: "report_claim",
      target: "artifact:report.html",
      sideEffects: ["artifact_write"],
      argumentHash: "arg_hash_1",
      authzId: "authz-1",
      actorId: "agent-1",
      obsRefs: ["obs_1", "obs_2"]
    });

    expect(details.confirmation.requiresReviewerReason).toBe(true);
    expect(details.visibleFields).toEqual([
      "provider",
      "action",
      "risk",
      "target",
      "side_effects",
      "actor",
      "authz",
      "argument_hash",
      "obs_refs"
    ]);
  });
});

describe("buildApprovalQueueRows", () => {
  it("shows reviewer-critical context before approve or deny actions", () => {
    const rows = buildApprovalQueueRows([
      {
        approvalId: "approval-1",
        provider: "runwarden.report.render",
        action: "render",
        risk: "report_claim",
        target: "artifact:report.html",
        sideEffects: ["artifact_write"],
        argumentHash: "arg_hash_1",
        authzId: "authz-1",
        actorId: "agent-1",
        obsRefs: ["obs_1"]
      }
    ]);

    const [row] = rows;
    expect(row).toBeDefined();
    expect(row!.visibleFields).toEqual([
      "provider",
      "action",
      "risk",
      "target",
      "side_effects",
      "actor",
      "authz",
      "argument_hash",
      "obs_refs"
    ]);
    expect(row!.actions).toEqual(["open_details", "approve", "deny"]);
    expect(row!.requiresReasonForDecision).toBe(true);
  });
});

describe("renderReviewerConsoleHtml", () => {
  it("renders a security workbench surface with approval context and details drawer", () => {
    const html = renderReviewerConsoleHtml(
      {
        sessionId: "session-1",
        riskStatus: "requires_review",
        traceIntegrity: "verified",
        pendingApprovalCount: 1,
        fastGateStatus: "passed",
        fullGateStatus: "missing"
      },
      [
        {
          approvalId: "approval-1",
          provider: "runwarden.report.render",
          action: "render",
          risk: "report_claim",
          target: "artifact:report.html",
          sideEffects: ["artifact_write"],
          argumentHash: "arg_hash_1",
          authzId: "authz-1",
          actorId: "agent-1",
          obsRefs: ["obs_1"]
        }
      ]
    );

    expect(html).toContain("runwarden-workbench");
    expect(html).toContain("nav-brand");
    expect(html).toContain("brand-mark\" aria-hidden=\"true\"");
    expect(html).toContain("command-bar");
    expect(html).toContain("Trusted side effects");
    expect(html).toContain('role="status" aria-label="Assessment status"');
    expect(html).toContain("Agent Boundary");
    expect(html).toContain("Provider Registry");
    expect(html).toContain("Accountability");
    expect(html).toContain("Assurance");
    expect(html).toContain('href="#assurance"');
    expect(html).toContain("Settings");
    expect(html).toContain("Approval Queue");
    expect(html).toContain("details-drawer");
    expect(html).toContain("runwarden.report.render");
    expect(html).toContain("render");
    expect(html).toContain("arg_hash_1");
    expect(html).toContain("approval-decision-form");
    expect(html).toContain("state-badge");
    expect(html).toContain("risk-chip");
    expect(html).toContain("module-partial");
    expect(html).toContain("1 pending");
    expect(html).toContain('tabindex="0"');
    expect(html).toContain('role="list"');
    expect(html).toContain('role="listitem"');
    expect(html).toContain('aria-current="true"');
    expect(html).toContain('aria-controls="approval-details"');
    expect(html).toContain('data-provider="runwarden.report.render"');
    expect(html).toContain('data-side-effects="artifact_write"');
    expect(html).toContain("data-action=\"approve\"");
    expect(html).not.toContain("<script");
  });

  it("does not expose approve or deny actions when no approval is selected", () => {
    const html = renderReviewerConsoleHtml({});

    expect((html.match(/No actions waiting for review/g) ?? []).length).toBe(1);
    expect(html).toContain("No actions waiting for review");
    expect(html).toContain("module-empty");
    expect(html).toContain("0 pending");
    expect(html).not.toContain('data-action="approve"');
    expect(html).not.toContain('data-action="deny"');
    expect(html).toContain('aria-label="Approval details"');
  });

  it("renders with the approved Runwarden design tokens", () => {
    const html = renderReviewerConsoleHtml({});

    expect(html).toContain('"IBM Plex Sans"');
    expect(html).toContain("#2f6f4e");
    expect(html).toContain("#f7f8f4");
    expect(html).toContain("#20241f");
    expect(html).toContain("repeating-linear-gradient");
    expect(html).toContain("position: sticky");
    expect(html).not.toContain("radial-gradient");
    expect(html).not.toContain("4vw");
  });

  it("escapes dynamic approval content before rendering", () => {
    const html = renderReviewerConsoleHtml(
      {},
      [
        {
          approvalId: "approval-1",
          provider: "<img src=x onerror=alert(1)>",
          action: "<svg onload=alert(1)>",
          risk: "high",
          target: "target",
          sideEffects: [],
          argumentHash: "hash",
          obsRefs: ["obs_<1>"]
        }
      ]
    );

    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(html).toContain("&lt;svg onload=alert(1)&gt;");
    expect(html).toContain("obs_&lt;1&gt;");
    expect(html).not.toContain("<img src=x");
  });
});
