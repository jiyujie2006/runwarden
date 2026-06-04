import { describe, expect, it } from "vitest";
import { renderReviewerConsoleHtml } from "./index";

describe("reviewer console browser contract", () => {
  it("renders responsive and accessible static HTML without script execution", () => {
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
          provider: "external.mcp.browser.open_page",
          action: "open_page",
          risk: "network_active",
          target: "https://example.com",
          sideEffects: ["network"],
          argumentHash: "arg_hash_1",
          authzId: "authz-1",
          actorId: "agent-1",
          obsRefs: ["obs_1"]
        }
      ]
    );

    expect(html).toContain('name="viewport"');
    expect(html).toContain('aria-label="Runwarden sections"');
    expect(html).toContain('aria-label="Approval details"');
    expect(html).toContain('role="status" aria-label="Assessment status"');
    expect(html).toContain("assurance-ops-shell");
    expect(html).toContain("assurance-map");
    expect(html).toContain("evidence-timeline");
    expect(html).toContain("queue-search");
    expect(html).toContain("[hidden] { display: none !important; }");
    expect(html).toContain("nav-brand");
    expect(html).toContain("command-bar");
    expect(html).toContain("state-badge");
    expect(html).toContain("risk-chip");
    expect(html).toContain("details-drawer");
    expect(html).toContain('aria-controls="approval-details"');
    expect(html).toContain('data-detail-fields');
    expect(html).toContain("@media (max-width: 768px)");
    expect(html).toContain("min-height: 44px");
    expect(html).toContain(":focus-visible");
    expect(html).toContain("<script");
    expect(html).toContain("filterApprovals");
  });
});
