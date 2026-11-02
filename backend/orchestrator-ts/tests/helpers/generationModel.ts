import type { LanguageModel } from "ai";

import type {
  ModelClient,
  ModelDecision,
  ModelDecisionRequest,
  StructuredObjectRequest,
} from "../../src/model/types.js";

export class ScriptedObjectModel implements ModelClient {
  readonly modelId = "scripted-object-model";
  readonly model = {} as LanguageModel;
  readonly requests: Array<StructuredObjectRequest<unknown>> = [];
  private readonly outputs: unknown[];

  constructor(outputs: unknown[]) {
    this.outputs = [...outputs];
  }

  async decide(_request: ModelDecisionRequest): Promise<ModelDecision> {
    throw new Error("ScriptedObjectModel only implements generateObject");
  }

  async generateObject<T>(request: StructuredObjectRequest<T>): Promise<T> {
    this.requests.push(request);
    const output = this.outputs.shift();
    if (output === undefined) {
      throw new Error("ScriptedObjectModel ran out of outputs");
    }
    return request.schema.parse(output);
  }
}
