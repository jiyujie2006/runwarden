import { describe, expect, it } from "vitest";
import * as configTools from "./index";
import {
  agentConfigCertCommand,
  agentConfigCheckFromCertReport,
  isAgentConfigCertPassed,
  parseAgentConfigCertReport
} from "./index";

describe("agent config cert report helpers", () => {
  it("does not export a TypeScript raw-config policy checker", () => {
    expect("checkRunwardenOnlyConfig" in configTools).toBe(false);
  });

  it("builds a Rust certifier command for agent config checks", () => {
    expect(agentConfigCertCommand("examples/agent-configs/claude.runwarden-only.json")).toEqual({
      command: "runwarden",
      args: [
        "cert",
        "agent-config",
        "examples/agent-configs/claude.runwarden-only.json",
        "--json"
      ]
    });
  });

  it("summarizes the Rust certifier report without re-evaluating the config", () => {
    const report = parseAgentConfigCertReport(
      JSON.stringify({
        passed: false,
        exposure: "raw_tool_exposure",
        findings: ["raw or downstream MCP exposed: shell (bash)"],
        side_effect_executed: false
      })
    );

    expect(isAgentConfigCertPassed(report)).toBe(false);
    expect(agentConfigCheckFromCertReport("claude", report)).toEqual({
      client: "claude",
      safe: false,
      exposure: "raw_tool_exposure",
      findings: ["raw or downstream MCP exposed: shell (bash)"],
      source: "rust-certifier"
    });
  });

  it("rejects malformed Rust certifier output", () => {
    expect(() =>
      parseAgentConfigCertReport(
        JSON.stringify({
          passed: true,
          exposure: "runwarden_only",
          findings: [],
          side_effect_executed: true
        })
      )
    ).toThrow("agent config cert report must have side_effect_executed=false");
  });

  it("keeps custom binary selection outside policy decisions", () => {
    expect(agentConfigCertCommand("config.json", { binary: "target/debug/runwarden" })).toEqual({
      command: "target/debug/runwarden",
      args: ["cert", "agent-config", "config.json", "--json"]
    });
  });
});
