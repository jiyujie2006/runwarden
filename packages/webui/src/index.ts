export const reviewerConsoleLayout = {
  shell: "security-workbench",
  regions: ["left-nav", "top-status-strip", "main-workspace", "details-drawer"],
  approvalPolicy: "high-risk-actions-confirm-in-details-drawer"
} as const;

export type RiskStatus = "allow" | "deny" | "requires_review" | "failed" | "incomplete";
export type TraceIntegrity = "verified" | "tampered" | "missing" | "incomplete";
export type GateStatus = "passed" | "failed" | "missing" | "running";
export type StatusTone = "neutral" | "success" | "review" | "danger" | "info";
export type ModuleState = "empty" | "loading" | "success" | "partial" | "error";

export interface ReviewerConsoleInput {
  sessionId?: string | null;
  riskStatus?: RiskStatus;
  traceIntegrity?: TraceIntegrity;
  pendingApprovalCount?: number | null;
  fastGateStatus?: GateStatus;
  fullGateStatus?: GateStatus;
  moduleStates?: Partial<Record<WorkbenchModuleId, WorkbenchModuleStateInput>>;
}

export interface StatusStripItem {
  id:
    | "session"
    | "risk"
    | "trace_integrity"
    | "pending_approvals"
    | "fast_gate"
    | "full_gate";
  label: string;
  value: string;
  tone: StatusTone;
}

export interface ReviewerConsoleViewModel {
  statusStrip: StatusStripItem[];
  modules: {
    agentBoundary: WorkbenchModule;
    providers: WorkbenchModule;
    approvals: WorkbenchModule;
    trace: WorkbenchModule;
    accountability: WorkbenchModule;
    reports: WorkbenchModule;
    artifacts: WorkbenchModule;
    assurance: WorkbenchModule;
    settings: WorkbenchModule;
  };
}

export interface WorkbenchModule {
  title: string;
  emptyState: string;
  state: ModuleState;
  message: string;
  errorIncludesSideEffectState: true;
  sideEffectExecuted: boolean;
  count: number | null;
}

export type WorkbenchModuleId =
  | "agentBoundary"
  | "providers"
  | "approvals"
  | "trace"
  | "accountability"
  | "reports"
  | "artifacts"
  | "assurance"
  | "settings";

export interface WorkbenchModuleStateInput {
  state: ModuleState;
  count?: number | null;
  message?: string;
  sideEffectExecuted?: boolean;
}

export const reviewerAccessibilityContract = {
  minTouchTargetPx: 44,
  contrast: "AA",
  keyboardFlows: ["left-nav", "module-tabs", "approval-row", "details-drawer", "decision-actions"],
  focusOrder: [
    "left-nav",
    "top-status-strip",
    "module-tabs",
    "approval-row",
    "details-drawer",
    "decision-actions"
  ]
} as const;

export interface TraceExplorerStreamInput {
  verified: boolean;
  exportedEventCount: number;
  totalMatching: number;
  nextOffset?: number | null;
  truncatedByBytes: boolean;
}

export interface TraceExplorerStreamModel {
  state: Extract<ModuleState, "success" | "partial" | "error">;
  progressLabel: string;
  nextAction: "load_more" | "raise_byte_budget" | "verify_trace";
  sideEffectExecuted: false;
}

export interface ApprovalDetailsInput {
  approvalId?: string;
  provider: string;
  risk: string;
  target: string;
  sideEffects: string[];
  argumentHash: string;
  authzId?: string | null;
  actorId?: string | null;
  obsRefs: string[];
}

export interface ApprovalQueueRow extends ApprovalDetailsInput {
  approvalId: string;
  visibleFields: ApprovalDetailsViewModel["visibleFields"];
  actions: Array<"open_details" | "approve" | "deny">;
  requiresReasonForDecision: true;
}

export interface ApprovalDetailsViewModel {
  title: string;
  visibleFields: Array<
    | "provider"
    | "risk"
    | "target"
    | "side_effects"
    | "actor"
    | "authz"
    | "argument_hash"
    | "obs_refs"
  >;
  summary: ApprovalDetailsInput;
  confirmation: {
    mode: "details-drawer";
    requiresReviewerReason: true;
    consumesApprovalOnConfirm: true;
  };
}

export function buildApprovalQueueRows(
  approvals: Array<ApprovalDetailsInput & { approvalId: string }>
): ApprovalQueueRow[] {
  return approvals.map((approval) => ({
    ...approval,
    visibleFields: approvalVisibleFields(),
    actions: ["open_details", "approve", "deny"],
    requiresReasonForDecision: true
  }));
}

export function createReviewerConsoleViewModel(
  input: ReviewerConsoleInput
): ReviewerConsoleViewModel {
  return {
    statusStrip: [
      {
        id: "session",
        label: "Session",
        value: input.sessionId ?? "No assessment loaded",
        tone: input.sessionId ? "neutral" : "review"
      },
      {
        id: "risk",
        label: "Risk",
        value: input.riskStatus ?? "incomplete",
        tone: toneForRisk(input.riskStatus ?? "incomplete")
      },
      {
        id: "trace_integrity",
        label: "Trace",
        value: input.traceIntegrity ?? "missing",
        tone: toneForTrace(input.traceIntegrity ?? "missing")
      },
      {
        id: "pending_approvals",
        label: "Approvals",
        value:
          input.pendingApprovalCount == null
            ? "unknown"
            : String(input.pendingApprovalCount),
        tone:
          input.pendingApprovalCount && input.pendingApprovalCount > 0
            ? "review"
            : "neutral"
      },
      {
        id: "fast_gate",
        label: "Fast Gate",
        value: input.fastGateStatus ?? "missing",
        tone: toneForGate(input.fastGateStatus ?? "missing")
      },
      {
        id: "full_gate",
        label: "Full Gate",
        value: input.fullGateStatus ?? "missing",
        tone: toneForGate(input.fullGateStatus ?? "missing")
      }
    ],
    modules: {
      agentBoundary: module(
        "Agent Boundary",
        "No agent config checked",
        null,
        input.moduleStates?.agentBoundary
      ),
      providers: module(
        "Provider Registry",
        "No providers allowed for this session",
        null,
        input.moduleStates?.providers
      ),
      approvals: module(
        "Approval Queue",
        "No actions waiting for review",
        null,
        input.moduleStates?.approvals
      ),
      trace: module(
        "Trace Explorer",
        "No trace events yet",
        null,
        input.moduleStates?.trace
      ),
      accountability: module(
        "Accountability",
        "No accountability chain reconstructed",
        null,
        input.moduleStates?.accountability
      ),
      reports: module("Reports", "No report rendered", null, input.moduleStates?.reports),
      artifacts: module(
        "Artifacts",
        "No artifacts generated",
        null,
        input.moduleStates?.artifacts
      ),
      assurance: module("Assurance", "No eval run yet", null, input.moduleStates?.assurance),
      settings: module(
        "Settings",
        "No local settings changed",
        null,
        input.moduleStates?.settings
      )
    }
  };
}

export function createTraceExplorerStreamModel(
  input: TraceExplorerStreamInput
): TraceExplorerStreamModel {
  if (!input.verified) {
    return {
      state: "error",
      progressLabel: "Trace verification failed",
      nextAction: "verify_trace",
      sideEffectExecuted: false
    };
  }

  const complete = input.nextOffset == null && !input.truncatedByBytes;
  return {
    state: complete ? "success" : "partial",
    progressLabel: `${input.exportedEventCount} / ${input.totalMatching} events`,
    nextAction: input.truncatedByBytes ? "raise_byte_budget" : "load_more",
    sideEffectExecuted: false
  };
}

export function buildApprovalDetails(
  input: ApprovalDetailsInput
): ApprovalDetailsViewModel {
  return {
    title: input.provider,
    visibleFields: approvalVisibleFields(),
    summary: input,
    confirmation: {
      mode: "details-drawer",
      requiresReviewerReason: true,
      consumesApprovalOnConfirm: true
    }
  };
}

export function renderReviewerConsoleHtml(
  input: ReviewerConsoleInput,
  approvals: Array<ApprovalDetailsInput & { approvalId: string }> = []
): string {
  const viewModel = createReviewerConsoleViewModel(input);
  const rows = buildApprovalQueueRows(approvals);
  const firstApproval = rows[0];

  return [
    "<!doctype html>",
    "<html lang=\"en\">",
    "<head>",
    "<meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    "<title>Runwarden Reviewer Console</title>",
    `<style>${workbenchCss()}</style>`,
    "</head>",
    "<body>",
    "<main class=\"runwarden-workbench\">",
    renderNav(),
    "<section class=\"workbench-main\" id=\"dashboard\" aria-label=\"Reviewer workspace\">",
    renderStatusStrip(viewModel.statusStrip),
    renderModules(viewModel, rows),
    "</section>",
    renderDetailsDrawer(firstApproval),
    "</main>",
    "</body>",
    "</html>"
  ].join("");
}

function approvalVisibleFields(): ApprovalDetailsViewModel["visibleFields"] {
  return [
    "provider",
    "risk",
    "target",
    "side_effects",
    "actor",
    "authz",
    "argument_hash",
    "obs_refs"
  ];
}

function renderNav(): string {
  const items = [
    "Dashboard",
    "Agent Boundary",
    "Provider Registry",
    "Approval Queue",
    "Trace Explorer",
    "Accountability",
    "Reports",
    "Artifacts",
    "Settings"
  ];
  return `<nav class="left-nav" aria-label="Runwarden sections">${items
    .map((item) => `<a href="#${slug(item)}">${escapeHtml(item)}</a>`)
    .join("")}</nav>`;
}

function renderStatusStrip(items: StatusStripItem[]): string {
  return `<header class="top-status-strip">${items
    .map(
      (item) =>
        `<div class="status-pill tone-${item.tone}"><span>${escapeHtml(
          item.label
        )}</span><strong>${escapeHtml(item.value)}</strong></div>`
    )
    .join("")}</header>`;
}

function renderModules(
  viewModel: ReviewerConsoleViewModel,
  approvals: ApprovalQueueRow[]
): string {
  return `<section class="workspace-grid">${renderModule(
    "agent-boundary",
    viewModel.modules.agentBoundary
  )}${renderModule("providers", viewModel.modules.providers)}${renderApprovalModule(
    approvals
  )}${renderModule("trace", viewModel.modules.trace)}${renderModule(
    "accountability",
    viewModel.modules.accountability
  )}${renderModule(
    "reports",
    viewModel.modules.reports
  )}${renderModule("artifacts", viewModel.modules.artifacts)}${renderModule(
    "assurance",
    viewModel.modules.assurance
  )}${renderModule(
    "settings",
    viewModel.modules.settings
  )}</section>`;
}

function renderApprovalModule(approvals: ApprovalQueueRow[]): string {
  const body =
    approvals.length === 0
      ? "<p>No actions waiting for review</p>"
      : approvals.map(renderApprovalRow).join("");
  return `<section class="module approval-module" id="approval-queue"><h2>Approval Queue</h2>${body}</section>`;
}

function renderApprovalRow(row: ApprovalQueueRow): string {
  return `<article class="approval-row" data-approval-id="${escapeAttr(
    row.approvalId
  )}"><div><h3>${escapeHtml(row.provider)}</h3><p>${escapeHtml(
    row.target
  )}</p></div><dl>${field("Risk", row.risk)}${field(
    "Actor",
    row.actorId ?? "unknown"
  )}${field("Authz", row.authzId ?? "none")}${field(
    "Argument",
    row.argumentHash
  )}${field("Obs", row.obsRefs.join(", "))}</dl><div class="row-actions"><button data-action="open_details">Open</button><button data-action="approve">Approve</button><button data-action="deny">Deny</button></div></article>`;
}

function renderModule(id: string, module: WorkbenchModule): string {
  return `<section class="module module-${module.state}" id="${escapeAttr(id)}"><h2>${escapeHtml(
    module.title
  )}</h2><p>${escapeHtml(module.message)}</p></section>`;
}

function renderDetailsDrawer(row: ApprovalQueueRow | undefined): string {
  if (!row) {
    return '<aside class="details-drawer" aria-label="Approval details"><h2>Approval Details</h2><p>Select an approval to review context.</p></aside>';
  }
  return `<aside class="details-drawer" aria-label="Approval details"><h2>${escapeHtml(
    row.provider
  )}</h2><dl>${field("Risk", row.risk)}${field("Target", row.target)}${field(
    "Side effects",
    row.sideEffects.join(", ") || "none"
  )}${field("Actor", row.actorId ?? "unknown")}${field(
    "Authz",
    row.authzId ?? "none"
  )}${field("Argument hash", row.argumentHash)}${field(
    "Obs refs",
    row.obsRefs.join(", ")
  )}</dl><label>Reason<textarea name="reason"></textarea></label></aside>`;
}

function field(label: string, value: string): string {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
}

function slug(input: string): string {
  return input.toLowerCase().replaceAll(" ", "-");
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

function workbenchCss(): string {
  return `
    :root { color-scheme: light; font-family: "IBM Plex Sans", system-ui, sans-serif; }
    body { margin: 0; background: #f7f8f4; color: #20241f; }
    .runwarden-workbench { min-height: 100vh; display: grid; grid-template-columns: 220px minmax(0, 1fr) 340px; }
    .left-nav { background: #151813; color: #f3faf5; padding: 18px; display: flex; flex-direction: column; gap: 6px; }
    .left-nav a { color: inherit; text-decoration: none; padding: 9px 10px; border-radius: 6px; min-height: 44px; box-sizing: border-box; display: flex; align-items: center; }
    .left-nav a:hover { background: #262d24; }
    .workbench-main { padding: 18px; min-width: 0; }
    .top-status-strip { display: grid; grid-template-columns: repeat(6, minmax(110px, 1fr)); gap: 8px; margin-bottom: 14px; }
    .status-pill { border: 1px solid #cdd5c8; background: #ffffff; border-radius: 6px; padding: 9px 10px; min-width: 0; }
    .status-pill span { display: block; font-size: 12px; color: #687064; }
    .status-pill strong { display: block; overflow-wrap: anywhere; font-size: 14px; }
    .tone-success { border-color: #1f7a4d; }
    .tone-review { border-color: #a76716; }
    .tone-danger { border-color: #b42318; }
    .tone-info { border-color: #2866a8; }
    .workspace-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .module { background: #ffffff; border: 1px solid #cdd5c8; border-radius: 6px; padding: 14px; min-width: 0; }
    .module h2, .details-drawer h2 { font-size: 16px; margin: 0 0 10px; }
    .approval-module { grid-column: 1 / -1; }
    .approval-row { border: 1px solid #cdd5c8; border-radius: 6px; padding: 12px; display: grid; grid-template-columns: minmax(180px, 1fr) minmax(260px, 2fr) auto; gap: 12px; align-items: start; }
    .approval-row h3 { margin: 0 0 4px; font-size: 15px; overflow-wrap: anywhere; }
    .approval-row p { margin: 0; color: #687064; overflow-wrap: anywhere; }
    dl { display: grid; gap: 7px; margin: 0; }
    dl div { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 8px; }
    dt { color: #687064; font-size: 12px; }
    dd { margin: 0; font-family: "JetBrains Mono", ui-monospace, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .row-actions { display: flex; gap: 6px; }
    button { border: 1px solid #cdd5c8; background: #ffffff; border-radius: 6px; min-height: 44px; padding: 8px 12px; }
    button:hover { border-color: #2f6f4e; background: #eef1ea; }
    button:focus-visible, .left-nav a:focus-visible { outline: 2px solid #2f6f4e; outline-offset: 2px; }
    .details-drawer { border-left: 1px solid #cdd5c8; background: #ffffff; padding: 18px; min-width: 0; }
    textarea { width: 100%; min-height: 82px; margin-top: 8px; box-sizing: border-box; }
    @media (max-width: 1199px) {
      .runwarden-workbench { grid-template-columns: 76px minmax(0, 1fr); }
      .left-nav a { font-size: 12px; }
      .details-drawer { grid-column: 1 / -1; border-left: 0; border-top: 1px solid #cdd5c8; }
      .top-status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 768px) {
      .runwarden-workbench { display: block; padding-bottom: 76px; }
      .left-nav { position: fixed; left: 0; right: 0; bottom: 0; z-index: 10; flex-direction: row; overflow-x: auto; padding: 8px 10px; border-top: 1px solid #cdd5c8; }
      .left-nav a { white-space: nowrap; }
      .top-status-strip, .workspace-grid { grid-template-columns: 1fr; }
      .approval-row { grid-template-columns: 1fr; }
      .details-drawer { min-height: calc(100vh - 76px); border-left: 0; border-top: 1px solid #cdd5c8; }
    }
  `;
}

function module(
  title: string,
  emptyState: string,
  count: number | null,
  override?: WorkbenchModuleStateInput
): WorkbenchModule {
  const state = override?.state ?? "empty";
  return {
    title,
    emptyState,
    state,
    message: override?.message ?? defaultModuleMessage(state, emptyState),
    errorIncludesSideEffectState: true,
    sideEffectExecuted: override?.sideEffectExecuted ?? false,
    count: override?.count ?? count
  };
}

function defaultModuleMessage(state: ModuleState, emptyState: string): string {
  switch (state) {
    case "loading":
      return "Loading";
    case "success":
      return "Loaded";
    case "partial":
      return "Partially loaded";
    case "error":
      return "Operation failed before trusted side effects";
    case "empty":
      return emptyState;
  }
}

function toneForRisk(risk: RiskStatus): StatusTone {
  switch (risk) {
    case "allow":
      return "success";
    case "requires_review":
      return "review";
    case "deny":
    case "failed":
      return "danger";
    case "incomplete":
      return "neutral";
  }
}

function toneForTrace(trace: TraceIntegrity): StatusTone {
  switch (trace) {
    case "verified":
      return "success";
    case "tampered":
      return "danger";
    case "incomplete":
      return "info";
    case "missing":
      return "review";
  }
}

function toneForGate(status: GateStatus): StatusTone {
  switch (status) {
    case "passed":
      return "success";
    case "failed":
      return "danger";
    case "running":
      return "info";
    case "missing":
      return "review";
  }
}
