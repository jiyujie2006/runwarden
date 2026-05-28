import { describe, expect, it } from "vitest";
import { encodeJsonRpcMessage } from "./index";

describe("encodeJsonRpcMessage", () => {
  it("uses MCP Content-Length framing", () => {
    const message = encodeJsonRpcMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });

    expect(message).toMatch(/^Content-Length: \d+\r\n\r\n/);
    expect(message).toContain("\"tools/list\"");
  });

  it("rejects non JSON serializable messages instead of emitting malformed frames", () => {
    expect(() => encodeJsonRpcMessage(undefined)).toThrow("message must serialize to JSON");
  });
});
