import { createHash } from "node:crypto";

import { makeRawOutputId } from "./ids.js";
import {
  RAW_OUTPUT_PREVIEW_CHARS,
  rawOutputRefSchema,
  type InternalAnalyzerName,
  type RawOutputRef,
} from "./schema/analyzer.js";

export interface RawOutputInput {
  analyzer: InternalAnalyzerName;
  pass: number;
  content: string;
}

/**
 * Full analyzer output lives outside graph state. State and model prompts keep
 * only a `RawOutputRef` with a short preview, so decompilation dumps or long
 * disassembly cannot flood the context window.
 */
export interface RawOutputStore {
  put(input: RawOutputInput): Promise<RawOutputRef>;
  get(ref: RawOutputRef | string): Promise<string | undefined>;
}

export class InMemoryRawOutputStore implements RawOutputStore {
  private readonly entries = new Map<string, string>();

  async put(input: RawOutputInput): Promise<RawOutputRef> {
    const sha256 = createHash("sha256").update(input.content).digest("hex");
    const ref = rawOutputRefSchema.parse({
      id: makeRawOutputId(input.analyzer, input.pass, input.content),
      analyzer: input.analyzer,
      pass: input.pass,
      bytes: Buffer.byteLength(input.content, "utf8"),
      sha256,
      preview: input.content.slice(0, RAW_OUTPUT_PREVIEW_CHARS),
    });
    this.entries.set(ref.id, input.content);
    return ref;
  }

  async get(ref: RawOutputRef | string): Promise<string | undefined> {
    const id = typeof ref === "string" ? ref : ref.id;
    return this.entries.get(id);
  }
}
