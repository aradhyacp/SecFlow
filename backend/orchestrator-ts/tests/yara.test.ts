import { describe, expect, it } from "vitest";

import { makeTargetId } from "../src/graph/ids.js";
import type { SecFlowResult } from "../src/graph/schema/analyzer.js";
import { generateYaraRules } from "../src/rules/generate.js";
import { validateYara } from "../src/rules/yaraValidator.js";
import { makeState, fixtureFindings } from "./helpers/analysisState.js";
import { ScriptedObjectModel } from "./helpers/generationModel.js";

const VALID_RULE = `rule SecFlow_Test_Payload {
  meta:
    description = "test payload indicator"
    author = "SecFlow"
    date = "2026-11-01"
  strings:
    $a = "payload.exe" ascii wide
  condition:
    any of them
}`;

const VALID_DRAFT = {
  reasoning: "The macro IOC contains payload.exe, which is concrete file content evidence.",
  rules: [
    {
      rule_name: "SecFlow_Test_Payload",
      description: "Detects the payload.exe string observed in macro evidence.",
      reasoning: "Derived from macro:pass1:finding2.",
      tags: ["malware", "macro"],
      evidence_refs: ["macro:pass1:finding2"],
      rule_text: VALID_RULE,
    },
  ],
};

function reconOnly(): SecFlowResult[] {
  return [fixtureFindings()[1]!];
}

describe("YARA validation", () => {
  it("compiles a syntactically valid rule with YARA-X", async () => {
    const result = await validateYara(VALID_RULE);
    expect(result.status).toBe("valid");
    expect(result.ruleNames).toEqual(["SecFlow_Test_Payload"]);
    expect(result.errors).toEqual([]);
  });

  it("rejects malformed rule syntax", async () => {
    const result = await validateYara('rule Broken { strings: $a = "x" condition: }');
    expect(result.status).toBe("invalid");
    expect(result.errors.length).toBeGreaterThan(0);
  });
});

describe("YARA generation", () => {
  it("generates a compiled, evidence-cited rule", async () => {
    const model = new ScriptedObjectModel([VALID_DRAFT]);
    const output = await generateYaraRules(makeState(), {
      model,
      now: () => new Date("2026-11-01T00:06:00.000Z"),
    });

    expect(output.status).toBe("generated");
    expect(output.rules).toHaveLength(1);
    expect(output.rules[0]).toMatchObject({
      kind: "yara",
      name: "SecFlow_Test_Payload",
      status: "valid",
      evidenceRefs: ["macro:pass1:finding2"],
    });
    expect(output.rules[0]?.validationErrors).toEqual([]);
    expect(model.requests).toHaveLength(1);
    expect(model.requests[0]?.prompt).toContain("<untrusted_evidence");
    expect(model.requests[0]?.prompt).toContain("payload.exe");
    expect(model.requests[0]?.prompt).not.toContain("/tmp/invoice.docm");
  });

  it("skips without calling the model when no file/content evidence exists", async () => {
    const model = new ScriptedObjectModel([]);
    const output = await generateYaraRules(makeState({}, reconOnly()), { model });

    expect(output.status).toBe("skipped");
    expect(output.reason).toContain("No file/content evidence");
    expect(model.requests).toHaveLength(0);
  });

  it("marks rules invalid when they cite an unknown evidence reference", async () => {
    const model = new ScriptedObjectModel([
      {
        ...VALID_DRAFT,
        rules: [{ ...VALID_DRAFT.rules[0], evidence_refs: ["macro:pass9:finding99"] }],
      },
    ]);
    const output = await generateYaraRules(makeState(), { model });

    expect(output.status).toBe("invalid");
    expect(output.rules[0]?.status).toBe("invalid");
    expect(output.rules[0]?.validationErrors.join(" ")).toContain("Unknown evidence_ref");
    expect(output.rules[0]?.evidenceRefs).toEqual([]);
  });

  it("rejects syntactically valid rules that invent a string not in evidence", async () => {
    const model = new ScriptedObjectModel([
      {
        ...VALID_DRAFT,
        rules: [
          {
            ...VALID_DRAFT.rules[0],
            rule_text: VALID_RULE.replace("payload.exe", "invented-not-in-evidence.exe"),
          },
        ],
      },
    ]);
    const output = await generateYaraRules(makeState(), { model });

    expect(output.status).toBe("invalid");
    expect(output.rules[0]?.status).toBe("invalid");
    expect(output.rules[0]?.validationErrors.join(" ")).toContain("not present");
  });

  it("records a generation failure instead of throwing", async () => {
    const model = new ScriptedObjectModel([]);
    const output = await generateYaraRules(makeState(), { model });

    expect(output.status).toBe("invalid");
    expect(output.error).toContain("ran out of outputs");
    expect(output.rules).toEqual([]);
  });

  it("keeps the target id trusted and never includes a path in prompt evidence", async () => {
    const model = new ScriptedObjectModel([VALID_DRAFT]);
    const state = makeState();
    await generateYaraRules(state, { model });
    const prompt = model.requests[0]?.prompt ?? "";
    expect(prompt).toContain(state.target.displayName);
    expect(prompt).not.toContain(state.target.value);
    expect(state.target.id).toBe(makeTargetId("file", "/tmp/invoice.docm"));
  });
});
