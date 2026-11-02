import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";

import init, { Compiler } from "@virustotal/yara-x";

export type YaraValidationStatus = "valid" | "invalid" | "unavailable";

export interface YaraValidationResult {
  status: YaraValidationStatus;
  errors: string[];
  warnings: string[];
  ruleNames: string[];
}

const RULE_NAME_RE = /\brule\s+([A-Za-z_][A-Za-z0-9_]*)/g;

let initialization: Promise<void> | undefined;

function initialize(): Promise<void> {
  initialization ??= (async () => {
    const require = createRequire(import.meta.url);
    const packagePath = require.resolve("@virustotal/yara-x/package.json");
    const wasmPath = path.join(path.dirname(packagePath), "pkg", "yara_x_js_bg.wasm");
    const wasm = await readFile(wasmPath);
    await init({ module_or_path: wasm });
  })();
  return initialization;
}

export function extractYaraRuleNames(source: string): string[] {
  return [...source.matchAll(RULE_NAME_RE)].map((match) => match[1] ?? "").filter(Boolean);
}

/**
 * Compile a rule with YARA-X. The WASM module is initialized once and reused.
 * Validator startup failure is reported as `unavailable`, not `invalid`, so a
 * missing optional tool cannot silently mark good rules as broken.
 */
export async function validateYara(source: string): Promise<YaraValidationResult> {
  const ruleNames = extractYaraRuleNames(source);
  try {
    await initialize();
  } catch (error) {
    return {
      status: "unavailable",
      errors: [
        `YARA-X validator unavailable: ${error instanceof Error ? error.message : String(error)}`,
      ],
      warnings: [],
      ruleNames,
    };
  }

  const compiler = new Compiler();
  try {
    compiler.addSource(source);
    // `build()` consumes the compiler; read warnings from Rules and do not
    // touch compiler.errors/compiler.warnings afterwards.
    const rules = compiler.build();
    const warnings = [...rules.warnings];
    rules.free();
    return {
      status: "valid",
      errors: [],
      warnings,
      ruleNames,
    };
  } catch (error) {
    return {
      status: "invalid",
      errors: [error instanceof Error ? error.message : String(error)],
      warnings: [],
      ruleNames,
    };
  } finally {
    try {
      compiler.free();
    } catch {
      // The compiler may have been consumed by build() before a failure.
    }
  }
}
