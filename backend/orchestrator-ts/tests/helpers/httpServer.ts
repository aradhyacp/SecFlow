import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface CapturedRequest {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
}

export interface TestServer {
  baseUrl: string;
  requests: CapturedRequest[];
  close(): Promise<void>;
}

export type TestHandler = (
  request: IncomingMessage,
  response: ServerResponse,
  body: Buffer,
) => void | Promise<void>;

export async function startTestServer(handler: TestHandler): Promise<TestServer> {
  const requests: CapturedRequest[] = [];
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      requests.push({
        method: request.method ?? "GET",
        url: request.url ?? "/",
        headers: request.headers,
      });
      void Promise.resolve(handler(request, response, Buffer.concat(chunks))).catch((error) => {
        response.statusCode = 500;
        response.end(`handler failed: ${String(error)}`);
      });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    requests,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

export function sendJson(response: ServerResponse, status: number, value: unknown): void {
  response.statusCode = status;
  response.setHeader("content-type", "application/json");
  response.end(JSON.stringify(value));
}
