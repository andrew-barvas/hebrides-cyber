// Shared runtime request-body validation (docs/ENHANCEMENTS.md E-06). Before
// this, the entire codebase validated req.body with `as {...}` — a
// compile-time cast that asserts a shape without checking it — followed by
// ad-hoc `if` checks of wildly varying rigour. Adopted incrementally: new
// routes first, existing ones backfilled opportunistically rather than in
// one big-bang rewrite.
import type { NextApiResponse } from "next";
import type { ZodType } from "zod";

/**
 * Validates `body` against `schema`. On success, returns the parsed, typed
 * value. On failure, writes a 400 response describing the first validation
 * issue and returns null — callers `return` immediately on a null result,
 * matching every other early-return-on-failure convention in this codebase.
 */
export function parseBody<T>(schema: ZodType<T>, body: unknown, res: NextApiResponse): T | null {
  const result = schema.safeParse(body);
  if (!result.success) {
    const issue = result.error.issues[0];
    const field = issue.path.join(".") || "body";
    res.status(400).json({ error: `${field}: ${issue.message}` });
    return null;
  }
  return result.data;
}
