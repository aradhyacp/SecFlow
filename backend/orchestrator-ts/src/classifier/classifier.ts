import { open } from "node:fs/promises";

import type { ResolvedInput } from "../pipeline/types.js";
import type { Classification, InputType } from "../graph/state.js";
import { HttpError } from "../http/errors.js";
import { makeTargetId } from "../graph/ids.js";
import type { AnalysisTarget } from "../graph/state.js";
import { classifyFile, classifyString } from "./rules.js";
import { sniffFile } from "./sniff.js";

const MAX_TARGET_LENGTH = 4_096;
const HEAD_BYTES = 4_096;

export interface ClassifiedInput {
  classification: Classification;
  inputType: InputType;
  target: AnalysisTarget;
}

async function readHead(filePath: string): Promise<Buffer> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    handle = await open(filePath, "r");
    const buffer = Buffer.alloc(HEAD_BYTES);
    const { bytesRead } = await handle.read(buffer, 0, HEAD_BYTES, 0);
    return buffer.subarray(0, bytesRead);
  } catch (error) {
    throw new HttpError(
      400,
      `Input file is not readable: ${error instanceof Error ? error.message : String(error)}`,
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Deterministic first-pass classification. Mirrors the Python classifier's
 * routing order (image → document → executable; URL → IP → domain) using magic
 * bytes instead of the `file`/python-magic binaries.
 */
export async function classifyInput(input: ResolvedInput): Promise<ClassifiedInput> {
  if (input.kind === "file") {
    const bytes = await readHead(input.value);
    const signature = sniffFile(bytes, input.originalName ?? input.displayName);
    const mimeType =
      signature.mimeType !== "application/octet-stream"
        ? signature.mimeType
        : (input.mimeType ?? signature.mimeType);
    const match = classifyFile(
      mimeType,
      signature.magicOutput,
      input.originalName ?? input.displayName,
    );

    const classification: Classification = {
      inputType: match?.inputType ?? "unknown",
      analyzer: match?.analyzer ?? null,
      mimeType,
      magicOutput: signature.magicOutput,
      deterministic: match !== null,
      ...(match?.reason
        ? { reasoning: match.reason }
        : { reasoning: "no deterministic file rule matched" }),
    };

    const target: AnalysisTarget = {
      id: makeTargetId("file", input.value),
      kind: "file",
      value: input.value,
      displayName: input.displayName,
      origin: "user_input",
      mimeType: classification.mimeType,
      ...(input.sizeBytes !== undefined ? { sizeBytes: input.sizeBytes } : {}),
    };

    return { classification, inputType: classification.inputType, target };
  }

  const value = input.value.trim();
  if (value.length === 0 || value.length > MAX_TARGET_LENGTH) {
    throw new HttpError(400, `Target must be 1–${MAX_TARGET_LENGTH} characters`);
  }

  const match = classifyString(value);
  const inputType: InputType = match?.inputType ?? "unknown";
  const classification: Classification = {
    inputType,
    analyzer: match?.analyzer ?? null,
    mimeType: "text/plain",
    magicOutput: value,
    deterministic: match !== null,
    ...(match?.reason
      ? { reasoning: match.reason }
      : { reasoning: "no deterministic string rule matched; model fallback required" }),
  };

  const target: AnalysisTarget = {
    id: makeTargetId(inputType === "unknown" ? "unknown" : inputType, value),
    kind: inputType === "unknown" ? "unknown" : inputType,
    value,
    displayName: value,
    origin: "user_input",
  };

  return { classification, inputType, target };
}
