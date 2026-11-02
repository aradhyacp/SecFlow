import { copyFile, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export interface PreparedUpload {
  path: string;
  cleanup(): Promise<void>;
}

/**
 * Some analyzers reject extensions outside a small allowlist. Use the original
 * file when it is already acceptable; otherwise analyze a temporary `.bin`
 * copy so the service sees a supported extension. The source upload is never
 * renamed in place.
 */
export async function withAllowedExtension(
  filePath: string,
  allowedExtensions: readonly string[],
): Promise<PreparedUpload> {
  const extension = path.extname(filePath).slice(1).toLowerCase();
  if (allowedExtensions.includes(extension)) {
    return { path: filePath, cleanup: async () => undefined };
  }

  const directory = await mkdtemp(path.join(os.tmpdir(), "secflow-upload-"));
  const target = path.join(directory, "upload.bin");
  await copyFile(filePath, target);

  return {
    path: target,
    cleanup: async () => {
      await rm(directory, { recursive: true, force: true });
    },
  };
}
