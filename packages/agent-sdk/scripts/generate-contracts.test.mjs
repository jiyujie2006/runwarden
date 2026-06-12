import { describe, expect, it } from "vitest";
import { contractsAreCurrent, normalizeNewlines } from "./generate-contracts.mjs";

describe("generate-contracts", () => {
  it("normalizes platform line endings before staleness checks", () => {
    const generated = "export interface Example {\n  value: string;\n}\n";

    expect(contractsAreCurrent(generated.replace(/\n/g, "\r\n"), generated)).toBe(true);
    expect(contractsAreCurrent(generated.replace(/\n/g, "\r"), generated)).toBe(true);
  });

  it("still reports stale contracts when generated content changes", () => {
    expect(contractsAreCurrent("export type A = string;\r\n", "export type A = number;\n")).toBe(false);
  });

  it("renders normalized newlines as LF", () => {
    expect(normalizeNewlines("a\r\nb\rc\n")).toBe("a\nb\nc\n");
  });
});
