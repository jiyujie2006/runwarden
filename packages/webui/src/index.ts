export type DemoDecision = "allowed" | "denied" | "requires_review";
export type DemoTraceState = "verified" | "tampered" | "missing";
export type DemoEventKind = "provider_call" | "model_call";

export interface DemoProviderCall {
  provider: string;
  action: string;
  decision: DemoDecision;
  execution_status: string;
  side_effect_executed: boolean;
  obs_ref?: string;
  reason?: string;
  error_kind?: string;
}

export interface DemoMetrics {
  trace_completeness: number;
  report_citation_accuracy: number;
}

export interface DemoReportClaim {
  id: string;
  text: string;
  obs_refs: string[];
}

export interface DemoReport {
  claims: DemoReportClaim[];
}

export interface DemoTimelineEvent {
  kind: DemoEventKind;
  scenario?: string;
  provider?: string;
  model?: string;
  action?: string;
  decision: string;
  execution_status?: string;
  side_effect_executed?: boolean;
  obs_ref?: string;
  reason?: string;
  error_kind?: string;
  anomaly?: {
    score: number;
    is_anomalous: boolean;
    reasons: string[];
  };
}

export interface DemoScenarioInput {
  scenario: string;
  provider_calls: DemoProviderCall[];
  denials: DemoProviderCall[];
  metrics: DemoMetrics;
  report: DemoReport;
  events?: DemoTimelineEvent[];
  trace?: unknown[];
  trace_verification?: { verified?: boolean };
  lint?: { ok: boolean };
}

export interface DemoScenarioSummary {
  scenario: string;
  providerCallCount: number;
  denialCount: number;
  reviewCount: number;
  blockedSideEffectCount: number;
  traceState: DemoTraceState;
  reportClaimCount: number;
  reportObsRefs: string[];
  metrics: DemoMetrics;
}

export interface DemoReviewerConsoleViewModel {
  suite: {
    scenarioCount: number;
    denialCount: number;
    reviewCount: number;
    blockedSideEffectCount: number;
    traceState: DemoTraceState;
  };
  scenarios: DemoScenarioSummary[];
  timeline: DemoTimelineEvent[];
  reviewQueue: DemoTimelineEvent[];
}

export function createDemoReviewerConsoleViewModel(
  inputs: DemoScenarioInput[]
): DemoReviewerConsoleViewModel {
  const scenarios: DemoScenarioSummary[] = inputs.map((input) => {
    const reviewCount = input.provider_calls.filter(
      (call) => call.decision === "requires_review"
    ).length;
    const blockedSideEffectCount = input.provider_calls.filter(
      (call) =>
        (call.decision === "denied" || call.decision === "requires_review") &&
        call.side_effect_executed === false
    ).length;
    const reportObsRefs = unique(
      input.report.claims.flatMap((claim) => claim.obs_refs)
    );

    const traceState = traceStateFromVerification(input.trace_verification);

    return {
      scenario: input.scenario,
      providerCallCount: input.provider_calls.length,
      denialCount: input.denials.length,
      reviewCount,
      blockedSideEffectCount,
      traceState,
      reportClaimCount: input.report.claims.length,
      reportObsRefs,
      metrics: input.metrics
    };
  });
  const timeline = inputs.flatMap(eventsFromScenario);

  return {
    suite: {
      scenarioCount: scenarios.length,
      denialCount: sum(scenarios, (scenario) => scenario.denialCount),
      reviewCount: sum(scenarios, (scenario) => scenario.reviewCount),
      blockedSideEffectCount: sum(
        scenarios,
        (scenario) => scenario.blockedSideEffectCount
      ),
      traceState: suiteTraceState(scenarios)
    },
    scenarios,
    timeline,
    reviewQueue: timeline.filter((event) => event.decision === "requires_review")
  };
}

export function renderDemoReviewerConsoleHtml(inputs: DemoScenarioInput[]): string {
  const model = createDemoReviewerConsoleViewModel(inputs);
  return [
    "<!doctype html>",
    "<html lang=\"en\">",
    "<head>",
    "<meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    "<title>Runwarden Contest Reviewer Console</title>",
    `<style>${styles()}</style>`,
    "</head>",
    "<body>",
    "<main class=\"console-shell\">",
    "<nav class=\"rail\" aria-label=\"Runwarden demo scenarios\"><strong>Runwarden</strong><span>contest range</span></nav>",
    "<section class=\"workspace\" aria-label=\"Reviewer workspace\">",
    "<header class=\"summary\" role=\"status\" aria-label=\"Demo suite status\">",
    `<h1>Contest Reviewer Console</h1>${statusPill("Scenarios", model.suite.scenarioCount)}${statusPill(
      "Denials",
      model.suite.denialCount
    )}${statusPill("Review", model.suite.reviewCount)}${statusPill(
      "Blocked",
      model.suite.blockedSideEffectCount
    )}${statusPill("Trace", model.suite.traceState)}`,
    "</header>",
    "<section class=\"scenario-grid\">",
    model.scenarios.map(renderScenarioCard).join(""),
    "</section>",
    "<section class=\"timeline\" aria-label=\"Security event timeline\">",
    "<h2>Security Events</h2>",
    model.timeline.length
      ? model.timeline.map(renderTimelineEvent).join("")
      : "<p>No security events.</p>",
    "</section>",
    "<section class=\"review-queue\" aria-label=\"Pending review queue\">",
    "<h2>Review Queue</h2>",
    model.reviewQueue.length
      ? model.reviewQueue.map(renderTimelineEvent).join("")
      : "<p>No pending reviews.</p>",
    "</section>",
    "</section>",
    "</main>",
    "</body>",
    "</html>"
  ].join("");
}

function renderScenarioCard(scenario: DemoScenarioSummary): string {
  return `<article class="scenario-card" aria-label="${escapeAttr(
    scenario.scenario
  )}"><header><h2>${escapeHtml(scenario.scenario)}</h2><span class="trace trace-${escapeAttr(
    scenario.traceState
  )}">${escapeHtml(scenario.traceState)}</span></header><dl>${fact(
    "Provider calls",
    String(scenario.providerCallCount)
  )}${fact("Denials", String(scenario.denialCount))}${fact(
    "Requires review",
    String(scenario.reviewCount)
  )}${fact("Blocked side effects", String(scenario.blockedSideEffectCount))}${fact(
    "Report claims",
    String(scenario.reportClaimCount)
  )}${fact(
    "Trace completeness",
    scenario.metrics.trace_completeness.toFixed(2)
  )}${fact(
    "Citation accuracy",
    scenario.metrics.report_citation_accuracy.toFixed(2)
  )}</dl><p class="obs">${escapeHtml(scenario.reportObsRefs.join(", "))}</p></article>`;
}

function renderTimelineEvent(event: DemoTimelineEvent): string {
  return `<article class="event event-${escapeAttr(event.decision)}"><header><strong>${escapeHtml(
    event.kind
  )}</strong><span>${escapeHtml(event.decision)}</span></header><dl>${event.scenario ? fact(
    "Scenario",
    event.scenario
  ) : ""}${event.provider ? fact("Provider", event.provider) : ""}${event.model ? fact(
    "Model",
    event.model
  ) : ""}${event.action ? fact("Action", event.action) : ""}${event.execution_status ? fact(
    "Status",
    event.execution_status
  ) : ""}${event.error_kind ? fact("Error", event.error_kind) : ""}${event.obs_ref ? fact(
    "Obs",
    event.obs_ref
  ) : ""}${typeof event.side_effect_executed === "boolean" ? fact(
    "Side effect",
    String(event.side_effect_executed)
  ) : ""}</dl>${event.reason ? `<p>${escapeHtml(event.reason)}</p>` : ""}</article>`;
}

function eventsFromScenario(input: DemoScenarioInput): DemoTimelineEvent[] {
  if (input.events?.length) {
    return input.events;
  }
  return input.provider_calls.map((call) => {
    const event: DemoTimelineEvent = {
      kind: "provider_call",
      scenario: input.scenario,
      provider: call.provider,
      action: call.action,
      decision: call.decision,
      execution_status: call.execution_status,
      side_effect_executed: call.side_effect_executed
    };
    if (call.obs_ref) event.obs_ref = call.obs_ref;
    if (call.reason) event.reason = call.reason;
    if (call.error_kind) event.error_kind = call.error_kind;
    return event;
  });
}

function statusPill(label: string, value: string | number): string {
  return `<div class="status-pill"><span>${escapeHtml(label)}</span><strong>${escapeHtml(
    String(value)
  )}</strong></div>`;
}

function fact(label: string, value: string): string {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function sum<T>(items: T[], read: (item: T) => number): number {
  return items.reduce((total, item) => total + read(item), 0);
}

function traceStateFromVerification(
  verification: DemoScenarioInput["trace_verification"]
): DemoTraceState {
  if (verification?.verified === true) {
    return "verified";
  }
  if (verification?.verified === false) {
    return "tampered";
  }
  return "missing";
}

function suiteTraceState(scenarios: DemoScenarioSummary[]): DemoTraceState {
  if (scenarios.length === 0) {
    return "missing";
  }
  if (scenarios.every((scenario) => scenario.traceState === "verified")) {
    return "verified";
  }
  if (scenarios.some((scenario) => scenario.traceState === "tampered")) {
    return "tampered";
  }
  return "missing";
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeAttr(value: string): string {
  return escapeHtml(value).replaceAll("'", "&#39;");
}

function styles(): string {
  return `
    :root {
      color-scheme: light;
      font-family: Inter, Aptos, system-ui, sans-serif;
      --ink: #20231f;
      --muted: #667064;
      --paper: #f7f8f4;
      --panel: #fffffb;
      --line: #cfd8ca;
      --rail: #171b15;
      --green: #25724d;
      --amber: #a76716;
      --red: #b42318;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-width: 320px;
      background:
        linear-gradient(90deg, rgba(23, 27, 21, 0.05) 1px, transparent 1px),
        linear-gradient(0deg, rgba(23, 27, 21, 0.04) 1px, transparent 1px),
        #f7f8f4;
      background-size: 28px 28px;
      color: var(--ink);
    }
    .console-shell {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 232px minmax(0, 1fr);
    }
    .rail {
      background: var(--rail);
      color: #f5fbf4;
      padding: 20px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .rail strong { font-size: 22px; }
    .rail span { color: #b9c6b8; }
    .workspace { padding: 22px; min-width: 0; }
    .summary {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) repeat(5, minmax(112px, 150px));
      gap: 10px;
      align-items: stretch;
      margin-bottom: 16px;
    }
    h1 { margin: 0; font-size: 34px; line-height: 1.05; }
    .status-pill, .scenario-card, .event {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 10px 30px rgba(32, 35, 31, 0.08);
    }
    .status-pill {
      min-height: 44px;
      padding: 10px 12px;
      border-top: 3px solid var(--green);
    }
    .status-pill span { display: block; color: var(--muted); font-size: 12px; }
    .status-pill strong { overflow-wrap: anywhere; }
    .scenario-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }
    .timeline, .review-queue { margin-top: 18px; }
    .timeline h2, .review-queue h2 { margin: 0 0 10px; }
    .scenario-card { padding: 16px; }
    .scenario-card header, .event header {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
      margin-bottom: 12px;
    }
    h2 { margin: 0; font-size: 19px; overflow-wrap: anywhere; }
    .event {
      padding: 14px;
      margin-bottom: 10px;
      border-left: 5px solid var(--green);
    }
    .event-denied { border-left-color: var(--red); }
    .event-requires_review { border-left-color: var(--amber); }
    .event-allowed { border-left-color: var(--green); }
    .event p { margin: 10px 0 0; color: var(--muted); overflow-wrap: anywhere; }
    .trace {
      border-radius: 999px;
      border: 1px solid var(--line);
      padding: 4px 8px;
      min-height: 28px;
      white-space: nowrap;
    }
    .trace-verified { color: var(--green); border-color: var(--green); }
    .trace-missing, .trace-tampered { color: var(--red); border-color: var(--red); }
    dl {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px;
      margin: 0;
    }
    dt { color: var(--muted); font-size: 12px; }
    dd { margin: 0; font-weight: 700; overflow-wrap: anywhere; }
    .obs {
      margin: 12px 0 0;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 12px;
    }
    :focus-visible { outline: 3px solid #2f6f4e; outline-offset: 3px; }
    @media (max-width: 900px) {
      .console-shell { grid-template-columns: 1fr; }
      .rail { position: sticky; top: 0; z-index: 1; }
      .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .summary h1 { grid-column: 1 / -1; }
      .scenario-grid { grid-template-columns: 1fr; }
    }
  `;
}
