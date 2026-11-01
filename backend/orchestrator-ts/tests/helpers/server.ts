import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import type { Express } from "express";

export function tempReportsDir(): string {
  return mkdtempSync(path.join(tmpdir(), "secflow-reports-"));
}

export interface TestServer {
  baseUrl: string;
  close: () => Promise<void>;
}

export async function startServer(app: Express): Promise<TestServer> {
  const server = app.listen(0, "127.0.0.1");
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("server did not bind to a TCP port");
  }

  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}
