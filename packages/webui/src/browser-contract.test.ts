import { describe, expect, it } from "vitest";
import { renderDemoReviewerConsoleHtml } from "./index";

describe("static demo console browser contract", () => {
  it("renders responsive accessible HTML for file based review", () => {
    const html = renderDemoReviewerConsoleHtml([
      {
        scenario: "environment-local-web-risk",
        provider_calls: [],
        denials: [],
        metrics: { trace_completeness: 1, report_citation_accuracy: 1 },
        report: { claims: [] },
        trace: [],
        lint: { ok: true }
      }
    ]);

    expect(html).toContain('name="viewport"');
    expect(html).toContain('aria-label="Runwarden demo scenarios"');
    expect(html).toContain('aria-label="Reviewer workspace"');
    expect(html).toContain('role="status" aria-label="Demo suite status"');
    expect(html).toContain("scenario-card");
    expect(html).toContain("trace-verified");
    expect(html).toContain(":focus-visible");
    expect(html).not.toContain("<script");
  });
});
