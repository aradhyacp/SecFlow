import type { ErrorRequestHandler, RequestHandler } from "express";

import multer from "multer";

import { HttpError, NotImplementedError, errorMessage } from "./errors.js";
import type { Logger } from "../logger.js";

/** flask-cors used `origins="*"`; keep the same permissive policy. */
export const corsMiddleware: RequestHandler = (req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }
  next();
};

export function createErrorHandler(logger: Logger): ErrorRequestHandler {
  return (error, req, res, _next) => {
    if (res.headersSent) {
      return;
    }

    let status = 500;
    let message = errorMessage(error);

    if (error instanceof HttpError) {
      status = error.status;
    } else if (error instanceof NotImplementedError) {
      status = 501;
    } else if (error instanceof multer.MulterError) {
      status = error.code === "LIMIT_FILE_SIZE" ? 413 : 400;
      message =
        error.code === "LIMIT_FILE_SIZE" ? "Uploaded file is too large" : `Upload error: ${error.message}`;
    }

    if (status >= 500) {
      logger.error(
        { err: error, status, method: req.method, url: req.originalUrl },
        "request failed",
      );
    }

    res.status(status).json({ error: message });
  };
}
