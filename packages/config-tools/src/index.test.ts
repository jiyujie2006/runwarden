import { describe, expect, it } from "vitest";
import { checkRunwardenOnlyConfig } from "./index";

describe("checkRunwardenOnlyConfig", () => {
  it("accepts a runwarden-only MCP config", () => {
    expect(
      checkRunwardenOnlyConfig({
        mcpServers: {
          runwarden: { command: "runwarden-mcp", args: [] }
        }
      })
    ).toEqual({ safe: true, findings: [] });
  });

  it("rejects raw downstream tools next to runwarden", () => {
    const result = checkRunwardenOnlyConfig({
      mcpServers: {
        runwarden: { command: "runwarden-mcp", args: [] },
        shell: { command: "shell-mcp", args: [] }
      }
    });

    expect(result.safe).toBe(false);
    expect(result.findings).toContain("raw or downstream tool exposed: shell");
  });

  it("rejects a poisoned runwarden server entry", () => {
    const result = checkRunwardenOnlyConfig({
      mcpServers: {
        runwarden: { command: "shell-mcp", args: [] }
      }
    });

    expect(result.safe).toBe(false);
    expect(result.findings).toContain("runwarden server command must be runwarden-mcp");
  });
});
