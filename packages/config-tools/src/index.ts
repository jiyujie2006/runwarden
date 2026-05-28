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
  const unsafe = names.filter((name) => name !== "runwarden");
  return {
    safe: unsafe.length === 0 && names.includes("runwarden"),
    findings: unsafe.map((name) => `raw or downstream tool exposed: ${name}`)
  };
}

