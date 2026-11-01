/** Errors that map directly onto an HTTP response. */
export class HttpError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

export class NotImplementedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotImplementedError";
  }
}

/** Analyzer calls that exhausted their retries or timed out. */
export class AnalyzerError extends Error {
  readonly analyzer: string;
  readonly retryable: boolean;

  constructor(analyzer: string, message: string, retryable = false) {
    super(message);
    this.name = "AnalyzerError";
    this.analyzer = analyzer;
    this.retryable = retryable;
  }
}

/** The model returned something that does not satisfy the decision schema. */
export class ModelContractError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ModelContractError";
  }
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
