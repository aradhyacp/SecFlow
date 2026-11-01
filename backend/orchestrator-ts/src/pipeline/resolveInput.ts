import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import multer from "multer";
import type { Request } from "express";

import type { AppConfig } from "../config.js";
import { HttpError } from "../http/errors.js";
import type { ResolvedInput } from "./types.js";

export const UPLOAD_DIR = path.join(os.tmpdir(), "secflow-orchestrator-uploads");

function safeOriginalName(originalName: string): string {
  const base = path.basename(originalName).replace(/[^A-Za-z0-9._-]/g, "_");
  const trimmed = base.replace(/^\.+/, "").slice(-120);
  return trimmed.length > 0 ? trimmed : "upload.bin";
}

/**
 * Multipart handling for POST /api/smart-analyze.
 * Files land on disk (never in memory) with a random prefix and the original
 * extension preserved, because analyzer services validate extensions.
 */
export function createUploadMiddleware(config: AppConfig): ReturnType<typeof multer> {
  mkdirSync(UPLOAD_DIR, { recursive: true });

  const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
    filename: (_req, file, cb) => {
      cb(null, `${randomUUID()}_${safeOriginalName(file.originalname)}`);
    },
  });

  return multer({
    storage,
    limits: { fileSize: config.maxUploadBytes, files: 1 },
  });
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * Resolve a request into either a temp file or a target string.
 * Mirrors the Python route: multipart "file", or JSON target/url/query.
 */
export async function resolveInput(req: Request, config: AppConfig): Promise<ResolvedInput> {
  const uploaded = req.file;
  if (uploaded) {
    if (!uploaded.originalname) {
      await unlink(uploaded.path).catch(() => undefined);
      throw new HttpError(400, "Uploaded file has no filename");
    }

    if (uploaded.size > config.maxUploadBytes) {
      await unlink(uploaded.path).catch(() => undefined);
      throw new HttpError(413, `Uploaded file exceeds ${config.maxUploadBytes} bytes`);
    }

    return {
      kind: "file",
      value: uploaded.path,
      displayName: safeOriginalName(uploaded.originalname),
      originalName: uploaded.originalname,
      mimeType: uploaded.mimetype,
      sizeBytes: uploaded.size,
      cleanup: async () => {
        await unlink(uploaded.path).catch(() => undefined);
      },
    };
  }

  if (req.is("application/json")) {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const candidate = body.target ?? body.url ?? body.query;
    if (!isNonEmptyString(candidate)) {
      throw new HttpError(400, "JSON body must contain 'target', 'url', or 'query' field");
    }
    const target = candidate.trim();
    return {
      kind: "target",
      value: target,
      displayName: target,
      cleanup: async () => undefined,
    };
  }

  throw new HttpError(400, "Provide 'file' (multipart/form-data) or 'target' (application/json)");
}
