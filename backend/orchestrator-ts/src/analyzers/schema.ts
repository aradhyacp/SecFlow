import { z } from "zod";

import { analyzerToolOutputSchema, secFlowResultSchema } from "../graph/schema/analyzer.js";

/**
 * Analyzer tools return two projections:
 * - `modelOutput` — concise, schema-validated result for the next model turn;
 * - `secFlow` — the full contract result appended to graph state and reports.
 *
 * The graph keeps `secFlow`; the model only ever sees `modelOutput`.
 */
export const analyzerToolResultSchema = z
  .object({
    modelOutput: analyzerToolOutputSchema,
    secFlow: secFlowResultSchema,
  })
  .strict();
export type AnalyzerToolResult = z.infer<typeof analyzerToolResultSchema>;
