import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { classifyInput, classifyString } from "../src/classifier/index.js";
import { HttpError } from "../src/http/errors.js";
import type { ResolvedInput } from "../src/pipeline/types.js";

let tempDir: string;

beforeAll(async () => {
  tempDir = await mkdtemp(path.join(os.tmpdir(), "secflow-classifier-test-"));
});

afterAll(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

function fileInput(filePath: string, displayName: string, mimeType?: string): ResolvedInput {
  return {
    kind: "file",
    value: filePath,
    displayName,
    originalName: displayName,
    ...(mimeType ? { mimeType } : {}),
    sizeBytes: 4,
    cleanup: async () => undefined,
  };
}

function targetInput(value: string): ResolvedInput {
  return {
    kind: "target",
    value,
    displayName: value,
    cleanup: async () => undefined,
  };
}

async function classifyBytes(
  name: string,
  bytes: Buffer,
  mimeType?: string,
): Promise<Awaited<ReturnType<typeof classifyInput>>> {
  const filePath = path.join(
    tempDir,
    `${Date.now()}-${Math.random().toString(16).slice(2)}-${name}`,
  );
  await writeFile(filePath, bytes);
  return classifyInput(fileInput(filePath, name, mimeType));
}

describe("deterministic string classification", () => {
  it("routes URLs before domains", () => {
    expect(classifyString("https://example.com/path")).toMatchObject({
      analyzer: "web",
      inputType: "url",
    });
    expect(classifyString("http://example.com")).toMatchObject({
      analyzer: "web",
      inputType: "url",
    });
  });

  it("routes IPs and domains to recon", () => {
    expect(classifyString("8.8.8.8")).toMatchObject({ analyzer: "recon", inputType: "ip" });
    expect(classifyString("example.com")).toMatchObject({
      analyzer: "recon",
      inputType: "domain",
    });
  });

  it("routes email and phone footprint inputs to recon", () => {
    expect(classifyString("user@example.com")).toMatchObject({
      analyzer: "recon",
      inputType: "email",
    });
    expect(classifyString("+14155552671")).toMatchObject({
      analyzer: "recon",
      inputType: "phone",
    });
  });

  it("returns null for unknown strings", () => {
    expect(classifyString("plain words")).toBeNull();
    expect(classifyString("http://")).toBeNull();
    expect(classifyString("")).toBeNull();
  });
});

describe("deterministic file classification", () => {
  it("recognizes images", async () => {
    const png = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]);
    const result = await classifyBytes("image.png", png);
    expect(result.classification).toMatchObject({
      analyzer: "steg",
      inputType: "image",
      deterministic: true,
      mimeType: "image/png",
    });
    expect(result.target).toMatchObject({ kind: "file", displayName: "image.png" });
  });

  it("recognizes Office Open XML documents by extension", async () => {
    const zip = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x00]);
    const result = await classifyBytes("invoice.docx", zip);
    expect(result.classification).toMatchObject({
      analyzer: "macro",
      inputType: "document",
      deterministic: true,
    });
  });

  it("recognizes OLE2 documents", async () => {
    const ole = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
    const result = await classifyBytes("legacy.doc", ole);
    expect(result.classification).toMatchObject({
      analyzer: "macro",
      inputType: "document",
    });
  });

  it("recognizes RTF documents", async () => {
    const rtf = Buffer.from("{\\rtf1\\ansi test}");
    const result = await classifyBytes("note.rtf", rtf);
    expect(result.classification).toMatchObject({
      analyzer: "macro",
      inputType: "document",
    });
  });

  it("recognizes PE and ELF executables", async () => {
    const pe = await classifyBytes("sample.exe", Buffer.from("MZ\x90\x00"));
    expect(pe.classification).toMatchObject({
      analyzer: "malware",
      inputType: "executable",
    });

    const elf = await classifyBytes("sample.bin", Buffer.from([0x7f, 0x45, 0x4c, 0x46]));
    expect(elf.classification).toMatchObject({
      analyzer: "malware",
      inputType: "executable",
    });
  });

  it("leaves unknown files eligible for model selection", async () => {
    const result = await classifyBytes("blob.dat", Buffer.from("not a known signature"));
    expect(result.classification).toMatchObject({
      analyzer: null,
      inputType: "unknown",
      deterministic: false,
    });
    expect(result.target.kind).toBe("file");
  });
});

describe("classifyInput validation", () => {
  it("rejects empty and oversized target strings", async () => {
    await expect(classifyInput(targetInput("   "))).rejects.toBeInstanceOf(HttpError);
    await expect(classifyInput(targetInput("a".repeat(4_097)))).rejects.toBeInstanceOf(HttpError);
  });

  it("marks arbitrary strings as unknown targets", async () => {
    const result = await classifyInput(targetInput("plain words"));
    expect(result.inputType).toBe("unknown");
    expect(result.target.kind).toBe("unknown");
    expect(result.classification.deterministic).toBe(false);
  });
});
