export interface AgentConfigCertReport {
  passed: boolean;
  exposure: string;
  findings: string[];
  side_effect_executed: false;
}

export interface AgentConfigCertCommandOptions {
  binary?: string;
  json?: boolean;
}

export interface AgentConfigCertCommand {
  command: string;
  args: string[];
}

export interface AgentConfigCheck {
  client: string;
  safe: boolean;
  exposure: string;
  findings: string[];
  source: "rust-certifier";
}

export function agentConfigCertCommand(
  inputPath: string,
  options: AgentConfigCertCommandOptions = {}
): AgentConfigCertCommand {
  if (inputPath.length === 0) {
    throw new Error("agent config input path is required");
  }

  const args = ["cert", "agent-config", inputPath];
  if (options.json ?? true) {
    args.push("--json");
  }

  return {
    command: options.binary ?? "runwarden",
    args
  };
}

export function parseAgentConfigCertReport(jsonText: string): AgentConfigCertReport {
  const value: unknown = JSON.parse(jsonText);
  if (!value || typeof value !== "object") {
    throw new Error("agent config cert report must be an object");
  }

  const report = value as Record<string, unknown>;
  if (typeof report.passed !== "boolean") {
    throw new Error("agent config cert report must include passed boolean");
  }
  if (typeof report.exposure !== "string") {
    throw new Error("agent config cert report must include exposure string");
  }
  if (
    !Array.isArray(report.findings) ||
    !report.findings.every((finding) => typeof finding === "string")
  ) {
    throw new Error("agent config cert report findings must be string[]");
  }
  if (report.side_effect_executed !== false) {
    throw new Error("agent config cert report must have side_effect_executed=false");
  }

  return {
    passed: report.passed,
    exposure: report.exposure,
    findings: report.findings,
    side_effect_executed: false
  };
}

export function isAgentConfigCertPassed(report: AgentConfigCertReport): boolean {
  return report.passed && report.side_effect_executed === false;
}

export function agentConfigCheckFromCertReport(
  client: string,
  report: AgentConfigCertReport
): AgentConfigCheck {
  return {
    client,
    safe: isAgentConfigCertPassed(report),
    exposure: report.exposure,
    findings: [...report.findings],
    source: "rust-certifier"
  };
}
