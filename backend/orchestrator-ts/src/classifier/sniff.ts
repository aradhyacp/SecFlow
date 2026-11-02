import path from "node:path";

export interface FileSignature {
  mimeType: string;
  magicOutput: string;
}

function startsWith(bytes: Buffer, signature: readonly number[], offset = 0): boolean {
  if (bytes.length < offset + signature.length) {
    return false;
  }
  return signature.every((value, index) => bytes[offset + index] === value);
}

function ascii(bytes: Buffer, start: number, length: number): string {
  return bytes.subarray(start, start + length).toString("latin1");
}

const IMAGE_SIGNATURES: Array<{
  match: (bytes: Buffer) => boolean;
  mimeType: string;
  label: string;
}> = [
  {
    match: (bytes) => startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    mimeType: "image/png",
    label: "PNG image data",
  },
  {
    match: (bytes) => startsWith(bytes, [0xff, 0xd8, 0xff]),
    mimeType: "image/jpeg",
    label: "JPEG image data",
  },
  {
    match: (bytes) => ascii(bytes, 0, 6) === "GIF87a" || ascii(bytes, 0, 6) === "GIF89a",
    mimeType: "image/gif",
    label: "GIF image data",
  },
  {
    match: (bytes) => ascii(bytes, 0, 2) === "BM",
    mimeType: "image/bmp",
    label: "PC bitmap",
  },
  {
    match: (bytes) =>
      startsWith(bytes, [0x49, 0x49, 0x2a, 0x00]) || startsWith(bytes, [0x4d, 0x4d, 0x00, 0x2a]),
    mimeType: "image/tiff",
    label: "TIFF image data",
  },
  {
    match: (bytes) => ascii(bytes, 0, 4) === "RIFF" && ascii(bytes, 8, 4) === "WEBP",
    mimeType: "image/webp",
    label: "Web/P image",
  },
];

/**
 * Identify common file types from magic bytes. This is the Node-side
 * replacement for the `file`/python-magic pair used by the Python classifier;
 * it deliberately covers only the types the routing rules need.
 */
export function sniffFile(bytes: Buffer, fileName: string): FileSignature {
  for (const signature of IMAGE_SIGNATURES) {
    if (signature.match(bytes)) {
      return { mimeType: signature.mimeType, magicOutput: signature.label };
    }
  }

  const extension = path.extname(fileName).slice(1).toLowerCase();

  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) || startsWith(bytes, [0x50, 0x4b, 0x05, 0x06])) {
    return { mimeType: "application/zip", magicOutput: "Zip archive data" };
  }

  if (startsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) {
    return {
      mimeType: "application/x-cfb",
      magicOutput: "Composite Document File V2 Document",
    };
  }

  if (ascii(bytes, 0, 5).toLowerCase() === "{\\rtf") {
    return { mimeType: "application/rtf", magicOutput: "Rich Text Format data" };
  }

  if (ascii(bytes, 0, 2) === "MZ") {
    return {
      mimeType: "application/vnd.microsoft.portable-executable",
      magicOutput: "PE32 executable (MS Windows)",
    };
  }

  if (startsWith(bytes, [0x7f, 0x45, 0x4c, 0x46])) {
    return { mimeType: "application/x-elf", magicOutput: "ELF executable" };
  }

  if (
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xce]) ||
    startsWith(bytes, [0xce, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xfe, 0xed, 0xfa, 0xcf]) ||
    startsWith(bytes, [0xcf, 0xfa, 0xed, 0xfe]) ||
    startsWith(bytes, [0xca, 0xfe, 0xba, 0xbe])
  ) {
    return { mimeType: "application/x-mach-binary", magicOutput: "Mach-O executable" };
  }

  if (extension === "rtf") {
    return { mimeType: "application/rtf", magicOutput: "Rich Text Format data" };
  }

  return { mimeType: "application/octet-stream", magicOutput: "" };
}
