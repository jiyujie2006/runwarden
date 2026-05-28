export interface AgentConfigCheck {
  safe: boolean;
  findings: string[];
}

export function checkRunwardenOnlyConfig(config: unknown): AgentConfigCheck {
  if (!config || typeof config !== "object" || !("mcpServers" in config)) {
    return { safe: false, findings: ["missing mcpServers"] };
  }
  const servers = (config as { mcpServers?: Record<string, unknown> }).mcpServers ?? {};
  const names = Object.keys(servers);
  const findings: string[] = [];
  for (const name of names) {
    if (name !== "runwarden") {
      findings.push(`raw or downstream tool exposed: ${name}`);
    }
  }
  const runwarden = servers.runwarden;
  if (!runwarden || typeof runwarden !== "object") {
    findings.push("runwarden server entry is required");
  } else {
    const server = runwarden as {
      command?: unknown;
      args?: unknown;
      env?: unknown;
      cwd?: unknown;
      url?: unknown;
      transport?: unknown;
    };
    if (server.command !== "runwarden-mcp") {
      findings.push("runwarden server command must be runwarden-mcp");
    }
    if (server.args !== undefined && (!Array.isArray(server.args) || server.args.length !== 0)) {
      findings.push("runwarden server args must be empty");
    }
    for (const field of ["env", "cwd", "url", "transport"] as const) {
      if (server[field] !== undefined) {
        findings.push(`runwarden server must not define ${field}`);
      }
    }
  }
  return {
    safe: findings.length === 0,
    findings
  };
}
