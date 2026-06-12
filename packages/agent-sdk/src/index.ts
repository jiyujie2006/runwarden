import type {
  ApprovalBinding,
  ApprovalRecord,
  ApprovalState,
  ArtifactRef,
  DecisionEnvelope,
  ErrorKind,
  ExecutionMode,
  ExecutionStatus,
  OperationError,
  OperationResultForProviderOutcome,
  OperationStatus,
  PolicyDecision,
  ProviderCall,
  ProviderOutcome,
  TraceExportPage,
  TraceQuery
} from "./generated/contracts";

export type {
  ApprovalBinding,
  ApprovalRecord,
  ApprovalState,
  ArtifactRef,
  DecisionEnvelope,
  ErrorKind,
  ExecutionMode,
  ExecutionStatus,
  OperationError,
  OperationResultForProviderOutcome,
  OperationStatus,
  PolicyDecision,
  ProviderCall,
  ProviderOutcome,
  TraceEvent,
  TraceExportPage,
  TracePage,
  TraceQuery
} from "./generated/contracts";

export interface ApprovalQueueResponse {
  approvals: ApprovalRecord[];
  side_effect_executed: false;
}

export interface OperationEnvelope<T> {
  operation: {
    ok: boolean;
    status: OperationStatus;
    data: T;
    error: OperationError | null;
    obs_refs: string[];
    artifacts: ArtifactRef[];
    next_actions: string[];
  };
  side_effect_executed: boolean;
}

export interface ApprovalReviewInput {
  reviewer: string;
  reason: string;
}

export interface ApprovalMutationResponse {
  approval: ApprovalRecord;
  side_effect_executed: boolean;
}

export interface SessionCreateInput {
  session_id: string;
  manifest_toml: string;
}

export interface TraceExportInput {
  trace_path: string;
  offset?: TraceQuery["offset"];
  limit?: TraceQuery["limit"];
  provider?: TraceQuery["provider"];
  event_type?: TraceQuery["event_type"];
  obs_prefix?: TraceQuery["obs_prefix"];
  max_bytes?: TraceQuery["max_bytes"];
}

export interface ReportLintInput {
  report_path: string;
  trace_path: string;
}

export interface ReportRenderInput extends ReportLintInput {
  format: "markdown" | "json" | "html" | "sarif";
}

export interface ArtifactVerifyInput {
  artifacts_path: string;
  manifest_path: string;
}

export interface ArtifactSubmissionInput {
  full?: boolean;
  output_path: string;
}

export interface EvalAgentNativeInput {
  config_paths?: string[];
}

export interface UiLaunchInput {
  bind: string;
  port: number;
  artifacts_path: string;
}

export interface AgentCheckConfigInput {
  client: string;
  input_path: string;
}

export interface FetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface FetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}

export type FetchFn = (url: string, init?: FetchInit) => Promise<FetchResponse>;

export interface RunwardenClientOptions {
  launchToken?: string;
  origin?: string;
  fetch?: FetchFn;
  allowRemoteLaunchToken?: boolean;
}

export class RunwardenClient {
  private readonly launchToken: string | undefined;
  private readonly origin: string;
  private readonly fetchFn: FetchFn;

  constructor(private readonly baseUrl: string, options: RunwardenClientOptions = {}) {
    const parsedBaseUrl = new URL(baseUrl);
    if (
      options.launchToken &&
      !options.allowRemoteLaunchToken &&
      !isLocalApiOrigin(parsedBaseUrl)
    ) {
      throw new Error("launchToken may only be used with local Runwarden API origins");
    }
    this.launchToken = options.launchToken;
    this.origin = options.origin ?? parsedBaseUrl.origin;
    this.fetchFn = options.fetch ?? defaultFetch();
  }

  async agentBootstrap(): Promise<Record<string, unknown>> {
    return {
      architecture: "agent_native_security_kernel",
      agent_only_sees_runwarden: true,
      all_tools_are_kernel_managed_providers: true,
      raw_side_effect_tools_allowed: false
    };
  }

  endpoint(path: string): string {
    return new URL(path, this.baseUrl).toString();
  }

  async approvalQueue(): Promise<ApprovalQueueResponse> {
    return this.request<ApprovalQueueResponse>("/approvals");
  }

  async sessionCreateFromManifest(input: SessionCreateInput): Promise<unknown> {
    return this.request("/sessions", "POST", input);
  }

  async providerList(sessionId?: string): Promise<unknown> {
    const query = sessionId ? `?session=${encodeURIComponent(sessionId)}` : "";
    return this.request(`/providers${query}`);
  }

  async providerStatus(provider: string): Promise<unknown> {
    return this.request(`/providers/${encodeURIComponent(provider)}/status`);
  }

  async providerCall(call: ProviderCall): Promise<unknown> {
    return this.request("/provider-calls", "POST", call);
  }

  async traceExport(input: TraceExportInput): Promise<TraceExportPage> {
    const response = await this.request<OperationEnvelope<TraceExportPage>>(
      "/trace/export",
      "POST",
      input
    );
    return response.operation.data;
  }

  async reportLint(input: ReportLintInput): Promise<unknown> {
    return this.request("/reports/lint", "POST", input);
  }

  async reportRender(input: ReportRenderInput): Promise<unknown> {
    return this.request("/reports/render", "POST", input);
  }

  async artifactVerify(input: ArtifactVerifyInput): Promise<unknown> {
    return this.request("/artifacts/verify", "POST", input);
  }

  async artifactSubmission(input: ArtifactSubmissionInput): Promise<unknown> {
    return this.request("/artifacts/submission", "POST", input);
  }

  async evalAgentNative(input: EvalAgentNativeInput = {}): Promise<unknown> {
    return this.request("/eval/agent-native", "POST", input);
  }

  async releaseSmoke(): Promise<unknown> {
    return this.request("/release/smoke", "POST");
  }

  async uiLaunch(input: UiLaunchInput): Promise<unknown> {
    return this.request("/ui/launch", "POST", input);
  }

  async agentCheckConfig(input: AgentCheckConfigInput): Promise<unknown> {
    return this.request("/agent/config/check", "POST", input);
  }

  async approveApproval(
    approvalId: string,
    input: ApprovalReviewInput
  ): Promise<ApprovalMutationResponse> {
    return this.request<ApprovalMutationResponse>(
      `/approvals/${encodeURIComponent(approvalId)}/approve`,
      "POST",
      input
    );
  }

  async denyApproval(
    approvalId: string,
    input: ApprovalReviewInput
  ): Promise<ApprovalMutationResponse> {
    return this.request<ApprovalMutationResponse>(
      `/approvals/${encodeURIComponent(approvalId)}/deny`,
      "POST",
      input
    );
  }

  private async request<T>(
    path: string,
    method = "GET",
    body?: unknown
  ): Promise<T> {
    const headers: Record<string, string> = {
      accept: "application/json",
      origin: this.origin
    };
    if (this.launchToken) {
      headers.authorization = `Bearer ${this.launchToken}`;
    }

    const init: FetchInit = { method, headers };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }

    const response = await this.fetchFn(this.endpoint(path), init);
    if (!response.ok) {
      throw new Error(`Runwarden Local API request failed with status ${response.status}`);
    }
    const payload = (await response.json()) as T;
    return payload;
  }
}

function isLocalApiOrigin(url: URL): boolean {
  const host = url.hostname.toLowerCase();
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host === "[::1]"
  );
}

function defaultFetch(): FetchFn {
  const fetchFn = (globalThis as unknown as { fetch?: FetchFn }).fetch;
  if (!fetchFn) {
    throw new Error("RunwardenClient requires a fetch implementation");
  }
  return fetchFn;
}
