export function encodeJsonRpcMessage(message: unknown): string {
  const body = JSON.stringify(message);
  return `Content-Length: ${new TextEncoder().encode(body).length}\r\n\r\n${body}`;
}

