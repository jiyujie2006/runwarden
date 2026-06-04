export const reviewerConsoleLayout = {
  shell: "security-workbench",
  regions: ["left-nav", "command-bar", "top-status-strip", "workbench-main", "details-drawer"],
  approvalPolicy: "high-risk-actions-confirm-in-details-drawer"
} as const;

export type RiskStatus = "allow" | "deny" | "requires_review" | "failed" | "incomplete";
export type TraceIntegrity = "verified" | "tampered" | "missing" | "incomplete";
export type GateStatus = "passed" | "failed" | "missing" | "running";
export type StatusTone = "neutral" | "success" | "review" | "danger" | "info";
export type ModuleState = "empty" | "loading" | "success" | "partial" | "error";

export interface ReviewerConsoleInput {
  sessionId?: string | null;
  localApiUrl?: string | null;
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
    "command-bar",
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
  action: string;
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
    | "action"
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
    `<main class="runwarden-workbench assurance-ops-shell" data-local-api-url="${escapeAttr(
      input.localApiUrl ?? ""
    )}">`,
    renderNav(),
    "<section class=\"workbench-main\" id=\"dashboard\" aria-label=\"Reviewer workspace\">",
    renderCommandBar(),
    renderStatusStrip(viewModel.statusStrip),
    renderModules(viewModel, rows),
    "</section>",
    renderDetailsDrawer(firstApproval),
    `<script>${reviewerConsoleJs()}</script>`,
    "</main>",
    "</body>",
    "</html>"
  ].join("");
}

function approvalVisibleFields(): ApprovalDetailsViewModel["visibleFields"] {
  return [
    "provider",
    "action",
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
    "Assurance",
    "Settings"
  ];
  return `<nav class="left-nav" aria-label="Runwarden sections"><div class="nav-brand"><span class="brand-mark" aria-hidden="true">RW</span><strong>Runwarden</strong><small>review console</small></div>${items
    .map((item) => `<a href="#${slug(item)}">${escapeHtml(item)}</a>`)
    .join("")}</nav>`;
}

function renderCommandBar(): string {
  return '<header class="command-bar"><div><p class="eyebrow">Assurance Operations</p><h1>Reviewer Console</h1></div><div class="command-meter"><span>Trusted side effects</span><strong>approval-gated by kernel evidence</strong></div></header>';
}

function renderStatusStrip(items: StatusStripItem[]): string {
  return `<header class="top-status-strip" role="status" aria-label="Assessment status">${items
    .map(
      (item) =>
        `<div class="status-pill tone-${item.tone}"><span class="status-label">${escapeHtml(
          item.label
        )}</span><strong>${escapeHtml(item.value)}</strong></div>`
    )
    .join("")}</header>`;
}

function renderModules(
  viewModel: ReviewerConsoleViewModel,
  approvals: ApprovalQueueRow[]
): string {
  return `<section class="assurance-ops-layout">${renderAssuranceMap(
    viewModel,
    approvals
  )}${renderEvidenceTimeline(viewModel, approvals)}${renderApprovalModule(
    approvals
  )}<section class="workspace-grid supporting-modules">${renderModule(
    "agent-boundary",
    viewModel.modules.agentBoundary
  )}${renderModule("providers", viewModel.modules.providers)}${renderApprovalSummary(
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
  )}${renderSettingsModule(viewModel.modules.settings)}</section></section>`;
}

function renderAssuranceMap(
  viewModel: ReviewerConsoleViewModel,
  approvals: ApprovalQueueRow[]
): string {
  const traceState = viewModel.modules.trace.state;
  const reportState = viewModel.modules.reports.state;
  const artifactState = viewModel.modules.artifacts.state;
  const assuranceState = viewModel.modules.assurance.state;
  return `<section class="assurance-map" id="assurance-map" aria-label="Assurance evidence map"><div class="module-head"><h2>Assurance Map</h2><span class="state-badge">${approvals.length} pending review</span></div><div class="assurance-nodes"><button type="button" class="assurance-node tone-info" data-detail-type="Kernel" data-detail-title="Kernel decision boundary" data-detail-body="Provider calls remain mediated by Runwarden kernel decisions before side effects."><span>Kernel</span><strong>policy gate</strong></button><button type="button" class="assurance-node tone-review" data-detail-type="Review" data-detail-title="Reviewer approval binding" data-detail-body="${escapeAttr(
    approvals.length === 0
      ? "No pending high-risk actions."
      : `${approvals.length} high-risk action${approvals.length === 1 ? "" : "s"} require visible context, reviewer identity, and reason.`
  )}"><span>Review</span><strong>${approvals.length} pending</strong></button><button type="button" class="assurance-node tone-success" data-detail-type="Trace" data-detail-title="Trace integrity" data-detail-body="Trace status is ${escapeAttr(
    traceState
  )}; report and approval claims must cite obs refs."><span>Trace</span><strong>${escapeHtml(
    traceState
  )}</strong></button><button type="button" class="assurance-node tone-info" data-detail-type="Artifacts" data-detail-title="Artifacts and reports" data-detail-body="Reports are ${escapeAttr(
    reportState
  )}; artifacts are ${escapeAttr(artifactState)}; assurance is ${escapeAttr(
    assuranceState
  )}."><span>Evidence</span><strong>${escapeHtml(assuranceState)}</strong></button></div></section>`;
}

function renderEvidenceTimeline(
  viewModel: ReviewerConsoleViewModel,
  approvals: ApprovalQueueRow[]
): string {
  const firstApproval = approvals[0];
  const rows: Array<[string, string]> = [
    ["session", viewModel.statusStrip[0]?.value ?? "No assessment loaded"],
    ["kernel", viewModel.statusStrip[1]?.value ?? "incomplete"],
    ["trace", viewModel.statusStrip[2]?.value ?? "missing"],
    ["approval", firstApproval?.approvalId ?? "no pending approval"],
    ["artifact", viewModel.modules.artifacts.message],
    ["assurance", viewModel.modules.assurance.message]
  ];
  return `<section class="evidence-timeline" id="evidence-timeline" aria-label="Evidence timeline"><div class="module-head"><h2>Evidence Timeline</h2><span class="state-badge">obs chain</span></div><ol>${rows
    .map(
      ([label, value]) =>
        `<li><span class="timeline-dot" aria-hidden="true"></span><strong>${escapeHtml(
          label
        )}</strong><code>${escapeHtml(value)}</code></li>`
    )
    .join("")}</ol></section>`;
}

function renderApprovalModule(approvals: ApprovalQueueRow[]): string {
  const body =
    approvals.length === 0
      ? "<p>No actions waiting for review</p>"
      : `<div class="approval-list" role="list">${approvals
          .map((row, index) => renderApprovalRow(row, index === 0))
          .join("")}</div>`;
  return `<section class="module approval-module review-queue-panel module-${approvals.length > 0 ? "partial" : "empty"}" id="approval-queue" data-filter-status="all"><div class="module-head"><h2>Approval Queue</h2><span class="state-badge">${approvals.length} pending</span></div><div class="queue-toolbar" role="search"><label class="queue-search">Search approvals<input type="search" data-approval-search placeholder="Provider, action, obs, hash"></label><div class="queue-filters" aria-label="Approval filters"><button type="button" data-approval-filter="all" aria-pressed="true">All</button><button type="button" data-approval-filter="requires_review">Review</button><button type="button" data-approval-filter="network">Network</button><button type="button" data-approval-filter="artifact">Artifact</button></div></div>${body}<p class="queue-empty" data-queue-empty hidden>No matching approvals.</p></section>`;
}

function renderApprovalSummary(approvals: ApprovalQueueRow[]): string {
  return `<section class="module module-${approvals.length > 0 ? "partial" : "empty"}" id="approval-summary"><div class="module-head"><h2>Approval Summary</h2><span class="state-badge">${approvals.length} pending</span></div><p>${escapeHtml(
    approvals.length === 0
      ? "No reviewer action is currently required."
      : "Pending actions require visible context, reviewer identity, and reason before approval is consumed."
  )}</p></section>`;
}

function renderApprovalRow(row: ApprovalQueueRow, selected = false): string {
  return `<article class="approval-row${selected ? " is-selected" : ""}" role="listitem" tabindex="0" aria-current="${selected ? "true" : "false"}" aria-controls="approval-details" aria-label="Review approval for ${escapeAttr(
    row.provider
  )}" data-approval-id="${escapeAttr(
    row.approvalId
  )}" data-provider="${escapeAttr(row.provider)}" data-action="${escapeAttr(row.action)}" data-risk="${escapeAttr(
    row.risk
  )}" data-target="${escapeAttr(row.target)}" data-side-effects="${escapeAttr(
    row.sideEffects.join(", ") || "none"
  )}" data-actor="${escapeAttr(row.actorId ?? "unknown")}" data-authz="${escapeAttr(
    row.authzId ?? "none"
  )}" data-argument-hash="${escapeAttr(row.argumentHash)}" data-obs-refs="${escapeAttr(
    row.obsRefs.join(", ")
  )}" data-search-text="${escapeAttr(
    [
      row.approvalId,
      row.provider,
      row.action,
      row.risk,
      row.target,
      row.sideEffects.join(" "),
      row.argumentHash,
      row.actorId ?? "",
      row.authzId ?? "",
      row.obsRefs.join(" ")
    ].join(" ")
  )}"><div><span class="risk-chip">${escapeHtml(row.risk)}</span><h3>${escapeHtml(row.provider)}</h3><p>${escapeHtml(
    row.target
  )}</p></div><dl>${field("Risk", row.risk)}${field(
    "Action",
    row.action
  )}${field(
    "Actor",
    row.actorId ?? "unknown"
  )}${field("Authz", row.authzId ?? "none")}${field(
    "Argument",
    row.argumentHash
  )}${field("Obs", row.obsRefs.join(", "))}</dl>${renderApprovalDecisionForm(
    row.approvalId
  )}</article>`;
}

function renderModule(id: string, module: WorkbenchModule): string {
  const count = module.count == null ? "" : `<span class="module-count">${module.count}</span>`;
  return `<section class="module module-${module.state}" id="${escapeAttr(id)}"><div class="module-head"><h2>${escapeHtml(
    module.title
  )}</h2><span class="state-badge">${escapeHtml(module.state)}</span>${count}</div><p>${escapeHtml(module.message)}</p></section>`;
}

function renderDetailsDrawer(row: ApprovalQueueRow | undefined): string {
  if (!row) {
    return '<aside class="details-drawer" id="approval-details" data-approval-details aria-label="Approval details"><h2 data-detail-title>Approval Details</h2><p>Select an approval to review context.</p></aside>';
  }
  return `<aside class="details-drawer" id="approval-details" data-approval-details aria-label="Approval details"><h2 data-detail-title>${escapeHtml(
    row.provider
  )}</h2><dl data-detail-fields>${field("Action", row.action)}${field("Risk", row.risk)}${field("Target", row.target)}${field(
    "Side effects",
    row.sideEffects.join(", ") || "none"
  )}${field("Actor", row.actorId ?? "unknown")}${field(
    "Authz",
    row.authzId ?? "none"
  )}${field("Argument hash", row.argumentHash)}${field(
    "Obs refs",
    row.obsRefs.join(", ")
  )}</dl>${renderApprovalDecisionForm(row.approvalId)}</aside>`;
}

function field(label: string, value: string): string {
  return `<div><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>`;
}

function renderApprovalDecisionForm(approvalId: string): string {
  return `<form class="approval-decision-form" data-approval-id="${escapeAttr(
    approvalId
  )}" novalidate><label>Reviewer<input name="reviewer" autocomplete="off" required></label><label>Reason<textarea name="reason" required></textarea></label><div class="decision-actions"><button type="submit" name="decision" value="approve" data-action="approve">Approve</button><button type="submit" name="decision" value="deny" data-action="deny">Deny</button></div><p class="decision-status" role="status" data-decision-status></p></form>`;
}

function renderSettingsModule(module: WorkbenchModule): string {
  return `<section class="module module-${module.state}" id="settings"><div class="module-head"><h2>${escapeHtml(
    module.title
  )}</h2><span class="state-badge">${escapeHtml(
    module.state
  )}</span></div><p>${escapeHtml(
    module.message
  )}</p><label>Local API Token<input id="local-api-token" name="local_api_token" type="password" autocomplete="off" spellcheck="false"></label></section>`;
}

function reviewerConsoleJs(): string {
  return String.raw`"use strict";
(() => {
  const root = document.querySelector(".runwarden-workbench");
  const apiRoot = root?.dataset.localApiUrl?.replace(/\/$/, "");
  const tokenInput = document.querySelector("#local-api-token");
  const details = document.querySelector("[data-approval-details]");
  const detailTitle = details?.querySelector("[data-detail-title]");
  const detailFields = details?.querySelector("[data-detail-fields]");
  const detailForm = details?.querySelector("form.approval-decision-form");
  const queue = document.querySelector(".review-queue-panel");
  const queueSearch = document.querySelector("[data-approval-search]");
  const queueEmpty = document.querySelector("[data-queue-empty]");

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#39;"
    })[char]);
  }

  function fieldHtml(label, value) {
    return "<div><dt>" + escapeHtml(label) + "</dt><dd>" + escapeHtml(value || "none") + "</dd></div>";
  }

  function statusFor(form) {
    return form.querySelector("[data-decision-status]");
  }

  function setStatus(form, text, state) {
    const status = statusFor(form);
    if (!status) return;
    status.textContent = text;
    if (state) status.dataset.state = state;
    else delete status.dataset.state;
  }

  function disableForm(form) {
    for (const control of form.querySelectorAll("input, textarea, button")) {
      control.disabled = true;
    }
    form.classList.add("decision-complete");
  }

  function enableForm(form) {
    for (const control of form.querySelectorAll("input, textarea, button")) {
      control.disabled = false;
    }
    form.classList.remove("decision-complete");
  }

  function matchingForms(approvalId) {
    return Array.from(document.querySelectorAll("form.approval-decision-form")).filter((form) => form.dataset.approvalId === approvalId);
  }

  function markApprovalComplete(approvalId, message) {
    for (const row of document.querySelectorAll(".approval-row")) {
      if (row.dataset.approvalId === approvalId) {
        row.dataset.decisionComplete = "true";
      }
    }
    for (const form of matchingForms(approvalId)) {
      setStatus(form, message, "success");
      disableForm(form);
    }
  }

  function syncDetails(row) {
    if (!details || !detailTitle || !detailFields || !detailForm) return;
    const approvalId = row.dataset.approvalId ?? "";
    detailTitle.textContent = row.dataset.provider || "Approval Details";
    detailFields.innerHTML = [
      fieldHtml("Approval", approvalId),
      fieldHtml("Provider", row.dataset.provider),
      fieldHtml("Action", row.dataset.action),
      fieldHtml("Risk", row.dataset.risk),
      fieldHtml("Target", row.dataset.target),
      fieldHtml("Side effects", row.dataset.sideEffects),
      fieldHtml("Actor", row.dataset.actor),
      fieldHtml("Authz", row.dataset.authz),
      fieldHtml("Argument hash", row.dataset.argumentHash),
      fieldHtml("Obs refs", row.dataset.obsRefs)
    ].join("");
    detailForm.dataset.approvalId = approvalId;
    detailForm.reset();
    enableForm(detailForm);
    setStatus(detailForm, "", "");
    if (row.dataset.decisionComplete === "true") {
      setStatus(detailForm, "Decision already recorded.", "success");
      disableForm(detailForm);
    }
  }

  function selectApproval(row) {
    for (const item of document.querySelectorAll(".approval-row")) {
      const selected = item === row;
      item.classList.toggle("is-selected", selected);
      item.setAttribute("aria-current", selected ? "true" : "false");
    }
    syncDetails(row);
  }

  function filterApprovals() {
    if (!queue) return;
    const term = (queueSearch?.value ?? "").trim().toLowerCase();
    const filter = queue.dataset.filterStatus ?? "all";
    let visible = 0;
    for (const row of queue.querySelectorAll(".approval-row")) {
      const haystack = (row.dataset.searchText ?? "").toLowerCase();
      const sideEffects = (row.dataset.sideEffects ?? "").toLowerCase();
      const risk = (row.dataset.risk ?? "").toLowerCase();
      const matchesTerm = !term || haystack.includes(term);
      const matchesFilter =
        filter === "all" ||
        risk.includes(filter) ||
        sideEffects.includes(filter);
      const show = matchesTerm && matchesFilter;
      row.hidden = !show;
      if (show) visible += 1;
    }
    if (queueEmpty) queueEmpty.hidden = visible !== 0;
  }

  function interactiveTarget(target) {
    return target instanceof Element && Boolean(target.closest("input, textarea, button, a, label"));
  }

  async function submitDecision(form, decision) {
    const approvalId = form.dataset.approvalId;
    const reviewer = form.elements.reviewer?.value?.trim() ?? "";
    const reason = form.elements.reason?.value?.trim() ?? "";
    const token = tokenInput?.value?.trim() ?? "";
    if (!apiRoot || !approvalId) {
      setStatus(form, "Local API endpoint is unavailable.", "error");
      return;
    }
    if (!token) {
      setStatus(form, "Local API token is required.", "error");
      tokenInput?.focus();
      return;
    }
    if (!reviewer || !reason) {
      setStatus(form, "Reviewer and reason are required.", "error");
      return;
    }
    setStatus(form, "Submitting decision...", "");
    const response = await fetch(apiRoot + "/approvals/" + encodeURIComponent(approvalId) + "/" + decision, {
      method: "POST",
      headers: {
        "authorization": "Bearer " + token,
        "content-type": "application/json"
      },
      body: JSON.stringify({ reviewer, reason })
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      setStatus(form, body.error ?? "Approval decision failed.", "error");
      return;
    }
    markApprovalComplete(approvalId, (decision === "approve" ? "Approval" : "Denial") + " recorded.");
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.classList.contains("approval-decision-form")) return;
    event.preventDefault();
    const submitter = event.submitter;
    const decision = submitter instanceof HTMLButtonElement ? submitter.value : "";
    if (decision !== "approve" && decision !== "deny") {
      setStatus(form, "Choose approve or deny.", "error");
      return;
    }
    submitDecision(form, decision).catch((error) => {
      setStatus(form, error instanceof Error ? error.message : "Approval decision failed.", "error");
    });
  });

  document.addEventListener("click", (event) => {
    const filterButton = event.target instanceof Element ? event.target.closest("[data-approval-filter]") : null;
    if (filterButton instanceof HTMLButtonElement && queue) {
      queue.dataset.filterStatus = filterButton.dataset.approvalFilter ?? "all";
      for (const button of queue.querySelectorAll("[data-approval-filter]")) {
        button.setAttribute("aria-pressed", button === filterButton ? "true" : "false");
      }
      filterApprovals();
      return;
    }
    const node = event.target instanceof Element ? event.target.closest(".assurance-node") : null;
    if (node instanceof HTMLElement && detailTitle && detailFields) {
      detailTitle.textContent = node.dataset.detailTitle || node.dataset.detailType || "Assurance detail";
      detailFields.innerHTML = fieldHtml(node.dataset.detailType || "Type", node.dataset.detailBody || "No detail available.");
      return;
    }
    if (interactiveTarget(event.target)) return;
    const row = event.target instanceof Element ? event.target.closest(".approval-row") : null;
    if (row instanceof HTMLElement) selectApproval(row);
  });

  document.addEventListener("keydown", (event) => {
    const row = event.target instanceof HTMLElement && event.target.classList.contains("approval-row") ? event.target : null;
    if (!row || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault();
    selectApproval(row);
  });

  queueSearch?.addEventListener("input", filterApprovals);

  const initialRow = document.querySelector(".approval-row.is-selected") ?? document.querySelector(".approval-row");
  if (initialRow instanceof HTMLElement) syncDetails(initialRow);
  filterApprovals();
})();`;
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
    :root {
      color-scheme: light;
      font-family: "IBM Plex Sans", "Aptos", sans-serif;
      --ink: #20241f;
      --muted: #626b61;
      --paper: #f7f8f4;
      --panel: #fffffb;
      --line: #cdd5c8;
      --rail: #151813;
      --rail-soft: #262d24;
      --green: #2f6f4e;
      --amber: #a76716;
      --red: #b42318;
      --blue: #2866a8;
      --shadow: 0 18px 48px rgba(32, 36, 31, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background:
        linear-gradient(90deg, rgba(21, 24, 19, 0.045) 1px, transparent 1px),
        linear-gradient(0deg, rgba(21, 24, 19, 0.035) 1px, transparent 1px),
        repeating-linear-gradient(135deg, rgba(47, 111, 78, 0.055) 0 1px, transparent 1px 18px),
        #f7f8f4;
      background-size: 28px 28px, 28px 28px, auto, auto;
      color: #20241f;
      font-size: 14px;
    }
    [hidden] { display: none !important; }
    section[id], article[id], aside[id] { scroll-margin-top: 86px; }
    .runwarden-workbench {
      min-height: 100vh;
      display: grid;
      grid-template-columns: 248px minmax(0, 1fr) minmax(320px, 360px);
    }
    .left-nav {
      position: sticky;
      top: 0;
      height: 100vh;
      background: #151813;
      color: #f3faf5;
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 6px;
      border-right: 1px solid rgba(255, 255, 255, 0.08);
    }
    .nav-brand {
      display: grid;
      grid-template-columns: 44px minmax(0, 1fr);
      gap: 10px;
      align-items: center;
      padding: 4px 0 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.12);
      margin-bottom: 10px;
    }
    .brand-mark {
      width: 44px;
      height: 44px;
      display: grid;
      place-items: center;
      border: 1px solid rgba(255, 255, 255, 0.28);
      border-radius: 8px;
      background: linear-gradient(145deg, rgba(47, 111, 78, 0.82), rgba(21, 24, 19, 0.55));
      font-family: "JetBrains Mono", ui-monospace, monospace;
      font-size: 13px;
    }
    .nav-brand strong, .nav-brand small { display: block; overflow-wrap: anywhere; }
    .nav-brand small { color: #b9c6b8; font-size: 12px; }
    .left-nav a {
      color: inherit;
      text-decoration: none;
      padding: 10px 12px;
      border-radius: 6px;
      min-height: 44px;
      display: flex;
      align-items: center;
      border: 1px solid transparent;
    }
    .left-nav a:hover { background: #262d24; border-color: rgba(255, 255, 255, 0.14); }
    .workbench-main { padding: 22px; min-width: 0; }
    .command-bar {
      display: flex;
      justify-content: space-between;
      gap: 18px;
      align-items: end;
      margin-bottom: 16px;
      padding: 20px;
      border: 1px solid rgba(205, 213, 200, 0.9);
      border-radius: 8px;
      background: rgba(255, 255, 251, 0.86);
      box-shadow: var(--shadow);
    }
    .eyebrow { margin: 0 0 4px; color: #626b61; font-size: 12px; text-transform: uppercase; }
    h1 { margin: 0; font-size: 40px; line-height: 1; }
    .command-meter {
      min-width: 220px;
      border-left: 4px solid #2f6f4e;
      padding: 10px 12px;
      background: #f7f8f4;
      border-radius: 6px;
    }
    .command-meter span { display: block; color: #626b61; font-size: 12px; }
    .command-meter strong { display: block; font-size: 15px; overflow-wrap: anywhere; }
    .top-status-strip {
      display: grid;
      grid-template-columns: repeat(6, minmax(116px, 1fr));
      gap: 10px;
      margin-bottom: 14px;
    }
    .status-pill {
      border: 1px solid #cdd5c8;
      background: #fffffb;
      border-radius: 8px;
      padding: 11px 12px;
      min-width: 0;
      box-shadow: 0 1px 0 rgba(32, 36, 31, 0.05);
      border-top-width: 3px;
    }
    .status-label { display: block; font-size: 12px; color: #626b61; }
    .status-pill strong { display: block; overflow-wrap: anywhere; font-size: 14px; }
    .tone-success { border-top-color: #1f7a4d; }
    .tone-review { border-top-color: #a76716; }
    .tone-danger { border-top-color: #b42318; }
    .tone-info { border-top-color: #2866a8; }
    .assurance-ops-layout {
      display: grid;
      grid-template-columns: minmax(240px, 0.8fr) minmax(320px, 1.1fr);
      gap: 14px;
      align-items: start;
    }
    .workspace-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
    .supporting-modules { grid-column: 1 / -1; }
    .module {
      background: rgba(255, 255, 251, 0.94);
      border: 1px solid #cdd5c8;
      border-radius: 8px;
      padding: 15px;
      min-width: 0;
      box-shadow: 0 10px 30px rgba(32, 36, 31, 0.07);
    }
    .module-head {
      display: flex;
      align-items: center;
      gap: 8px;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .module h2, .details-drawer h2 { font-size: 16px; margin: 0; }
    .module p, .details-drawer p { margin: 0; color: #626b61; overflow-wrap: anywhere; }
    .state-badge, .module-count, .risk-chip {
      border: 1px solid #cdd5c8;
      border-radius: 999px;
      padding: 4px 8px;
      color: #626b61;
      background: #f7f8f4;
      font-size: 12px;
      white-space: nowrap;
    }
    .module-success .state-badge { color: #1f7a4d; border-color: #1f7a4d; }
    .module-error .state-badge { color: #b42318; border-color: #b42318; }
    .module-partial .state-badge { color: #a76716; border-color: #a76716; }
    .assurance-map, .evidence-timeline {
      background: rgba(255, 255, 251, 0.94);
      border: 1px solid #cdd5c8;
      border-radius: 8px;
      padding: 15px;
      min-width: 0;
      box-shadow: 0 10px 30px rgba(32, 36, 31, 0.07);
    }
    .assurance-nodes {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .assurance-node {
      display: grid;
      gap: 4px;
      align-content: start;
      text-align: left;
      background: #f7f8f4;
      border-radius: 8px;
      min-height: 86px;
      padding: 12px;
      border-top-width: 3px;
    }
    .assurance-node span {
      color: #626b61;
      font-size: 12px;
      text-transform: uppercase;
    }
    .assurance-node strong { overflow-wrap: anywhere; }
    .evidence-timeline ol {
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 0;
    }
    .evidence-timeline li {
      position: relative;
      display: grid;
      grid-template-columns: 16px 82px minmax(0, 1fr);
      gap: 8px;
      align-items: start;
      min-height: 38px;
      padding: 6px 0;
      border-bottom: 1px solid #e3e8df;
    }
    .evidence-timeline li:last-child { border-bottom: 0; }
    .timeline-dot {
      width: 9px;
      height: 9px;
      border-radius: 999px;
      background: #2f6f4e;
      margin-top: 4px;
      box-shadow: 0 0 0 3px rgba(47, 111, 78, 0.14);
    }
    .evidence-timeline strong {
      color: #626b61;
      font-size: 12px;
      text-transform: uppercase;
    }
    .evidence-timeline code {
      font-family: "JetBrains Mono", "IBM Plex Mono", ui-monospace, monospace;
      font-size: 12px;
      overflow-wrap: anywhere;
    }
    .approval-module { grid-column: 1 / -1; }
    .review-queue-panel { grid-column: 1 / -1; }
    .queue-toolbar {
      display: grid;
      grid-template-columns: minmax(220px, 1fr) auto;
      gap: 12px;
      align-items: end;
      margin-bottom: 12px;
      padding-bottom: 12px;
      border-bottom: 1px solid #e3e8df;
    }
    .queue-search { margin: 0; }
    .queue-search input { min-height: 44px; }
    .queue-filters {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      justify-content: flex-end;
    }
    .queue-filters button[aria-pressed="true"] {
      background: #2f6f4e;
      color: #f3faf5;
      border-color: #2f6f4e;
    }
    .queue-empty { margin-top: 10px; }
    .approval-row {
      border: 1px solid #cdd5c8;
      border-radius: 8px;
      padding: 13px;
      display: grid;
      grid-template-columns: minmax(180px, 1fr) minmax(260px, 2fr) minmax(220px, auto);
      gap: 14px;
      align-items: start;
      background: #fffffb;
      cursor: pointer;
      transition: border-color 120ms ease, box-shadow 120ms ease, background-color 120ms ease;
    }
    .approval-row:hover { border-color: rgba(47, 111, 78, 0.55); }
    .approval-row.is-selected {
      border-color: #2f6f4e;
      background: #fbfdf9;
      box-shadow: inset 4px 0 0 #2f6f4e, 0 10px 24px rgba(32, 36, 31, 0.08);
    }
    .approval-row + .approval-row { margin-top: 10px; }
    .approval-row h3 { margin: 8px 0 4px; font-size: 15px; overflow-wrap: anywhere; }
    .approval-row p { margin: 0; color: #626b61; overflow-wrap: anywhere; }
    dl { display: grid; gap: 7px; margin: 0; }
    dl div { display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: 8px; }
    dt { color: #626b61; font-size: 12px; }
    dd { margin: 0; font-family: "JetBrains Mono", "IBM Plex Mono", ui-monospace, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .row-actions, .decision-actions { display: flex; gap: 6px; flex-wrap: wrap; }
    .approval-decision-form { display: grid; gap: 8px; }
    button {
      border: 1px solid #cdd5c8;
      background: #fffffb;
      border-radius: 6px;
      min-height: 44px;
      padding: 8px 12px;
      color: #20241f;
    }
    button:hover { border-color: #2f6f4e; background: #eef1ea; }
    button:focus-visible, input:focus-visible, textarea:focus-visible, .left-nav a:focus-visible, .approval-row:focus-visible { outline: 2px solid #2f6f4e; outline-offset: 2px; }
    .details-drawer {
      border-left: 1px solid #cdd5c8;
      background: #fffffb;
      padding: 22px 18px;
      min-width: 0;
      box-shadow: -12px 0 34px rgba(32, 36, 31, 0.06);
      position: sticky;
      top: 0;
      height: 100vh;
      overflow: auto;
    }
    label { display: block; margin: 12px 0 6px; font-size: 12px; color: #626b61; }
    input, textarea {
      width: 100%;
      min-height: 38px;
      margin-top: 8px;
      box-sizing: border-box;
      border: 1px solid #cdd5c8;
      border-radius: 6px;
      padding: 8px;
      background: #fffffb;
      color: #20241f;
    }
    textarea { min-height: 82px; resize: vertical; }
    .decision-status { min-height: 20px; color: #20241f; overflow-wrap: anywhere; }
    .decision-status[data-state="error"] { color: #b42318; }
    .decision-status[data-state="success"] { color: #1f7a4d; }
    .decision-complete { opacity: 0.78; }
    @media (max-width: 1199px) {
      .runwarden-workbench { grid-template-columns: 86px minmax(0, 1fr); }
      .nav-brand { grid-template-columns: 1fr; }
      .nav-brand strong, .nav-brand small { display: none; }
      .left-nav a { font-size: 12px; padding-inline: 8px; }
      .details-drawer { grid-column: 1 / -1; border-left: 0; border-top: 1px solid #cdd5c8; position: static; height: auto; overflow: visible; }
      .top-status-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .assurance-ops-layout { grid-template-columns: 1fr; }
    }
    @media (max-width: 768px) {
      .runwarden-workbench { display: block; }
      .left-nav { position: sticky; top: 0; height: auto; z-index: 10; flex-direction: row; overflow-x: auto; padding: 8px 10px; border-right: 0; border-bottom: 1px solid #cdd5c8; box-shadow: 0 10px 22px rgba(32, 36, 31, 0.18); scrollbar-width: thin; }
      .nav-brand { display: none; }
      .left-nav a { white-space: nowrap; }
      h1 { font-size: 30px; }
      .command-bar { display: block; padding: 16px; }
      .command-meter { min-width: 0; margin-top: 12px; }
      .top-status-strip, .workspace-grid, .assurance-nodes, .queue-toolbar { grid-template-columns: 1fr; }
      .queue-filters { justify-content: flex-start; }
      .approval-row { grid-template-columns: 1fr; }
      .details-drawer { min-height: 0; border-left: 0; border-top: 1px solid #cdd5c8; }
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
