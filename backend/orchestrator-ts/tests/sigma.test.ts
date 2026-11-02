import { describe, expect, it } from "vitest";

import type { SecFlowResult } from "../src/graph/schema/analyzer.js";
import { generateSigmaRules } from "../src/rules/generate.js";
import { validateSigma } from "../src/rules/sigmaValidator.js";
import { makeState } from "./helpers/analysisState.js";
import { ScriptedObjectModel } from "./helpers/generationModel.js";

const VALID_RULE = `title: SecFlow Suspicious Payload Download
id: 123e4567-e89b-42d3-a456-426614174000
status: experimental
description: Detects a request for the payload path observed during analysis.
author: SecFlow
date: 2026/11/01
modified: 2026/11/01
tags:
  - attack.execution
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains: 'recongraph.xyz'
  condition: selection
falsepositives:
  - Unknown
level: high
`;

const VALID_DRAFT = {
  reasoning: "The macro IOC contains a concrete payload URL and hostname.",
  rules: [
    {
      rule_name: "SecFlow Suspicious Payload Download",
      description: "Detects the observed payload hostname at the proxy.",
      log_source: "proxy",
      reasoning: "Derived from macro:pass1:finding2.",
      tags: ["attack.execution"],
      evidence_refs: ["macro:pass1:finding2"],
      rule_text: VALID_RULE,
    },
  ],
};

function infoOnly(): SecFlowResult[] {
  return [
    {
      analyzer: "recon",
      pass: 1,
      input: "8.8.8.8",
      findings: [
        {
          type: "geolocation",
          detail: "IP geolocation: country=US, ISP=Example",
          severity: "info",
        },
      ],
      risk_score: 0,
      raw_output: "clean",
    },
  ];
}

describe("SIGMA validation", () => {
  it("validates required SIGMA fields", () => {
    const result = validateSigma(VALID_RULE);
    expect(result.status).toBe("valid");
    expect(result.title).toBe("SecFlow Suspicious Payload Download");
    expect(result.logSource).toBe("proxy");
    expect(result.errors).toEqual([]);
  });

  it("rejects malformed YAML and missing detection fields", () => {
    expect(validateSigma("title: [unclosed").status).toBe("invalid");
    expect(validateSigma("title: Missing fields\nid: nope").errors.length).toBeGreaterThan(0);
    expect(
      validateSigma(`title: Missing detection
id: 123e4567-e89b-42d3-a456-426614174000
logsource:
  category: proxy
`).errors.join(" "),
    ).toContain("detection");
    expect(
      validateSigma(`title: No selection
id: 123e4567-e89b-42d3-a456-426614174000
logsource:
  category: proxy
detection:
  condition: selection
`).errors.join(" "),
    ).toContain("selection");
  });
});

describe("SIGMA generation", () => {
  it("generates a structurally valid, evidence-cited rule", async () => {
    const model = new ScriptedObjectModel([VALID_DRAFT]);
    const output = await generateSigmaRules(makeState(), {
      model,
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    expect(output.status).toBe("generated");
    expect(output.rules[0]).toMatchObject({
      kind: "sigma",
      name: "SecFlow Suspicious Payload Download",
      status: "valid",
      evidenceRefs: ["macro:pass1:finding2"],
    });
    expect(output.rules[0]?.validationErrors).toEqual([]);
    expect(model.requests[0]?.prompt).toContain("recongraph.xyz");
    expect(model.requests[0]?.prompt).not.toContain("/tmp/invoice.docm");
  });

  it("skips without calling the model when no relevant log/network evidence exists", async () => {
    const model = new ScriptedObjectModel([]);
    const output = await generateSigmaRules(makeState({ indicators: [] }, infoOnly()), { model });

    expect(output.status).toBe("skipped");
    expect(output.reason).toContain("No relevant network");
    expect(model.requests).toHaveLength(0);
  });

  it("marks malformed generated rules invalid", async () => {
    const model = new ScriptedObjectModel([
      {
        ...VALID_DRAFT,
        rules: [{ ...VALID_DRAFT.rules[0], rule_text: "title: [unclosed" }],
      },
    ]);
    const output = await generateSigmaRules(makeState(), { model });

    expect(output.status).toBe("invalid");
    expect(output.rules[0]?.status).toBe("invalid");
    expect(output.rules[0]?.validationErrors.join(" ")).toContain("YAML");
  });

  it("marks structurally valid rules invalid when they invent a concrete indicator", async () => {
    const model = new ScriptedObjectModel([
      {
        ...VALID_DRAFT,
        rules: [
          {
            ...VALID_DRAFT.rules[0],
            rule_text: VALID_RULE.replace(
              "c-uri|contains: 'recongraph.xyz'",
              "c-uri|contains: 'invented.example'",
            ),
          },
        ],
      },
    ]);
    const output = await generateSigmaRules(makeState(), { model });

    expect(output.status).toBe("invalid");
    expect(output.rules[0]?.status).toBe("invalid");
    expect(output.rules[0]?.validationErrors.join(" ")).toContain("not present");
  });

  it("marks rules invalid when they cite an unknown evidence reference", async () => {
    const model = new ScriptedObjectModel([
      {
        ...VALID_DRAFT,
        rules: [{ ...VALID_DRAFT.rules[0], evidence_refs: ["web:pass9:finding99"] }],
      },
    ]);
    const output = await generateSigmaRules(makeState(), { model });

    expect(output.status).toBe("invalid");
    expect(output.rules[0]?.status).toBe("invalid");
    expect(output.rules[0]?.validationErrors.join(" ")).toContain("Unknown evidence_ref");
  });
});
