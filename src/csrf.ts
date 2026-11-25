
import type { RequestHandler } from "express";
import { sendErrorPage } from "./errors.ts";
import {timingSafeEqual} from "node:crypto"

export function validateRequestOrigin(appOrigin: string): RequestHandler {
  return (req, res, next) => {
    if (req.method !== "POST") {
      return next();
    }

    const origin = req.get("Origin");

    if (origin !== undefined) {
      if (origin === appOrigin) {
        return next();
      }

      return sendErrorPage(
        res,
        403,
        "Forbidden",
        "The request did not come from the app.",
      );
    }

    const referer = req.get("Referer");

    if (referer) {
      try {
        if (new URL(referer).origin === appOrigin) {
          return next();
        }
      } catch {
        // Invalid Referer URL.
      }
    }

    return sendErrorPage(
      res,
      403,
      "Forbidden",
      "The request did not come from the app.",
    );
  };
}


export function csrfTokensMatch(
  expected: string,
  actual: unknown,
): boolean {
  if (typeof actual !== "string") {
    return false;
  }

  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);

  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return timingSafeEqual(expectedBuffer, actualBuffer);
}
