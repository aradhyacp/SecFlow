import { z } from "zod";

import { defineTool } from "../tools.js";

export const lookupTestIndicatorInput = z.object({
  indicator: z.string().trim().min(3).max(255),
  kind: z.enum(["ip", "domain", "hash"]),
});

export type LookupTestIndicatorInput = z.infer<typeof lookupTestIndicatorInput>;

/**
 * Deterministic stand-in for a real analyzer tool. It exists only to prove the
 * model → tool → result → model cycle before real analyzers are wired in
 * (Step 6); it performs no network access.
 */
export const lookupTestIndicator = defineTool<LookupTestIndicatorInput>({
  name: "lookup_test_indicator",
  description:
    "Look up a synthetic threat-intelligence verdict for one indicator. Use this when the target is an IP address, domain, or file hash. Returns a risk score from 0 to 10 and a short note. This is a proof-of-concept tool and does not contact external services.",
  inputSchema: lookupTestIndicatorInput,
  async execute(input) {
    const riskScore = input.kind === "ip" ? 2.5 : input.kind === "domain" ? 5 : 7.5;
    return {
      indicator: input.indicator,
      kind: input.kind,
      riskScore,
      note: "Synthetic POC verdict; no external lookup was performed.",
    };
  },
});
