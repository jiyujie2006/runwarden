const textEncoder = new TextEncoder();

export function encodeJsonRpcMessage(message: unknown): string {
  const body = JSON.stringify(message);
  if (typeof body !== "string") {
    throw new TypeError("message must serialize to JSON");
  }
  return `Content-Length: ${textEncoder.encode(body).length}\r\n\r\n${body}`;
}
