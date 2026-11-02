import { Annotation } from "@langchain/langgraph";
import type { BaseMessage } from "@langchain/core/messages";

import type { ModelUsage } from "../../model/types.js";
import { addUsage, zeroUsage } from "../../model/usage.js";
import type { ToolFailureKind } from "../tools.js";

export type PocStatus = "running" | "completed" | "max_cycles";

export interface PocExecution {
  toolCallId: string;
  toolName: string;
  ok: boolean;
  input: unknown;
  output?: unknown;
  error?: string;
  failureKind?: ToolFailureKind;
  durationMs: number;
}

function appendMessages(left: BaseMessage[], right: BaseMessage | BaseMessage[]): BaseMessage[] {
  return left.concat(Array.isArray(right) ? right : [right]);
}

function appendItems<T>(left: T[], right: T | T[]): T[] {
  return left.concat(Array.isArray(right) ? right : [right]);
}

function replace<T>(_current: T, next: T): T {
  return next;
}

/**
 * State for the Step 4 proof-of-concept graph. It carries the full message
 * history so the provider sees prior tool results, plus the bounded-cycle
 * bookkeeping the graph routes on.
 */
export const PocStateAnnotation = Annotation.Root({
  messages: Annotation<BaseMessage[]>({
    reducer: appendMessages,
    default: () => [],
  }),
  cycles: Annotation<number>({
    reducer: replace,
    default: () => 0,
  }),
  status: Annotation<PocStatus>({
    reducer: replace,
    default: () => "running",
  }),
  finalText: Annotation<string>({
    reducer: replace,
    default: () => "",
  }),
  usage: Annotation<ModelUsage>({
    reducer: addUsage,
    default: zeroUsage,
  }),
  executions: Annotation<PocExecution[]>({
    reducer: appendItems,
    default: () => [],
  }),
});

export type PocState = typeof PocStateAnnotation.State;
