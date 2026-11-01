import { describe, expect, it } from "vitest";

import { redactSensitive } from "../src/logger.js";

describe("redactSensitive", () => {
  it("redacts OpenAI/OpenRouter style keys", () => {
    const value = "key sk-or-v1-abcdef1234567890 and sk-proj-abcdef1234567890";
    expect(redactSensitive(value)).toBe("key [REDACTED] and [REDACTED]");
  });

  it("redacts long hex strings (hashes, tokens)", () => {
    expect(redactSensitive("token=0123456789abcdef0123456789abcdef")).toBe("token=[REDACTED]");
  });

  it("leaves ordinary text alone", () => {
    expect(redactSensitive("recongraph.xyz payload.exe")).toBe("recongraph.xyz payload.exe");
  });
});
