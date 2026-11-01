import { z } from "zod";
import { describe, expect, it } from "vitest";

import { loadConfig } from "../../src/config.js";
import { createLogger } from "../../src/logger.js";
import { createModelClient } from "../../src/model/provider.js";

const apiKey = process.env.OPENROUTER_API_KEY;
const describeLive = apiKey ? describe : describe.skip;

/**
 * Live provider gate (Step 3 exit criterion).
 *
 * Runs only when OPENROUTER_API_KEY is present:
 *   OPENROUTER_API_KEY=... npm test
 */
describeLive("OpenRouter live provider", () => {
  it(
    "returns a schema-validated structured object",
    async () => {
      const config = loadConfig({
        NODE_ENV: "test",
        OPENROUTER_API_KEY: apiKey,
        OPENROUTER_MODEL: process.env.OPENROUTER_MODEL ?? "openai/gpt-4.1-mini",
        MODEL_TIMEOUT_MS: "60000",
        MODEL_MAX_RETRIES: "1",
      });
      const client = createModelClient(config, createLogger(config));

      const result = await client.generateObject({
        system: "You classify security analysis inputs. Answer with the schema only.",
        prompt: "Classify this target: 8.8.8.8",
        schema: z.object({
          kind: z.enum(["ip", "domain", "url", "file", "unknown"]),
          reason: z.string(),
        }),
        temperature: 0,
        maxOutputTokens: 200,
      });

      expect(result.kind).toBe("ip");
      expect(result.reason.length).toBeGreaterThan(0);
    },
    90_000,
  );
});
