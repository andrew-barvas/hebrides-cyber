// POST/GET/DELETE /api/account/api-spec — manages OpenAPI/Swagger specs
// stored against a target URL for spec-aware security testing (E-33).
//
// POST: accepts { target_url, spec_url } (URL to fetch) or
//       { target_url, spec_content } (raw JSON). Validates that the spec
//       is a parseable OpenAPI 2/3 document and stores it.
// GET:  returns specs for the authenticated user.
// DELETE: removes a spec by id.
//
// Same pattern as connect-repo.ts/target-auth.ts: writes go through
// supabaseAdmin (service role) because the table's RLS is read-only from
// the browser, and the route does validation before writing.
import type { NextApiRequest, NextApiResponse } from "next";
import { z } from "zod";
import { authenticateApiRequest, supabaseAdmin } from "@/lib/apiAuth";
import { parseBody } from "@/lib/validate";

const SPEC_FETCH_TIMEOUT_MS = 15_000;

// A generous but finite cap — a 50MB OpenAPI spec is either adversarial or
// an accidental Swagger UI bundle upload, not a real API contract.
const MAX_SPEC_SIZE_BYTES = 5 * 1024 * 1024;

const postBodySchema = z.union([
  z.object({
    target_url: z.string().url("target_url must be a valid URL"),
    spec_url: z.string().url("spec_url must be a valid URL"),
  }),
  z.object({
    target_url: z.string().url("target_url must be a valid URL"),
    spec_content: z.record(z.string(), z.unknown()).refine(
      (v) => Object.keys(v).length > 0,
      "spec_content must be a non-empty JSON object"
    ),
  }),
]);

const deleteBodySchema = z.object({
  id: z.string().uuid("id must be a valid UUID"),
});

type SpecFormat = "openapi3" | "openapi2" | "swagger";

/**
 * Detects the spec format and validates it has the minimum structure needed
 * for the scanner to do useful work (a `paths` object with at least one
 * entry). Deliberately lenient on everything else — we're a scanner, not
 * a spec linter, and rejecting a valid-but-unusual spec costs more than
 * accepting one that has slightly unusual structure.
 */
function detectFormat(spec: Record<string, unknown>): { format: SpecFormat; endpointCount: number } | { error: string } {
  const paths = spec.paths;
  if (!paths || typeof paths !== "object" || Array.isArray(paths)) {
    return { error: "Spec has no 'paths' object — not a valid OpenAPI/Swagger document." };
  }

  const endpointCount = Object.keys(paths).length;
  if (endpointCount === 0) {
    return { error: "Spec has an empty 'paths' object — no endpoints to test." };
  }

  if (typeof spec.openapi === "string" && spec.openapi.startsWith("3")) {
    return { format: "openapi3", endpointCount };
  }
  if (typeof spec.swagger === "string" && spec.swagger.startsWith("2")) {
    return { format: "openapi2", endpointCount };
  }
  // Fallback: if it has paths but no version key, treat it as openapi3 since
  // most modern specs are, and the scanner's path-walking logic is the same.
  if (typeof spec.openapi === "string" || typeof spec.swagger === "string") {
    return { format: "swagger", endpointCount };
  }
  return { error: "Spec must have an 'openapi' or 'swagger' top-level key." };
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST" && req.method !== "GET" && req.method !== "DELETE") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const caller = await authenticateApiRequest(req);
  if (!caller) return res.status(401).json({ error: "Missing or invalid Authorization header" });

  // ---------- GET: list specs for this user ----------
  if (req.method === "GET") {
    const { data, error } = await supabaseAdmin
      .from("api_specs")
      .select("id, target_url, spec_format, source_url, created_at, updated_at, spec_content")
      .eq("owner", caller.ownerId)
      .order("updated_at", { ascending: false });

    if (error) return res.status(500).json({ error: error.message });

    // Return a summary rather than the full spec content to keep the
    // payload size reasonable — the scanner reads spec_content itself.
    const specs = (data ?? []).map((row) => {
      const content = row.spec_content as Record<string, unknown> | null;
      const paths = content?.paths;
      const endpointCount = paths && typeof paths === "object" && !Array.isArray(paths)
        ? Object.keys(paths).length
        : 0;
      return {
        id: row.id,
        target_url: row.target_url,
        spec_format: row.spec_format,
        source_url: row.source_url,
        endpoint_count: endpointCount,
        created_at: row.created_at,
        updated_at: row.updated_at,
      };
    });

    return res.status(200).json({ specs });
  }

  // ---------- DELETE: remove by id ----------
  if (req.method === "DELETE") {
    const parsed = parseBody(deleteBodySchema, req.body, res);
    if (!parsed) return;

    const { error } = await supabaseAdmin
      .from("api_specs")
      .delete()
      .eq("id", parsed.id)
      .eq("owner", caller.ownerId);

    if (error) return res.status(500).json({ error: error.message });
    return res.status(200).json({ ok: true });
  }

  // ---------- POST: import a spec ----------
  const parsed = parseBody(postBodySchema, req.body, res);
  if (!parsed) return;

  const { target_url } = parsed;
  let specContent: Record<string, unknown>;
  let sourceUrl: string | null = null;

  if ("spec_url" in parsed) {
    // Fetch the spec from a URL
    sourceUrl = parsed.spec_url;
    try {
      const fetchRes = await fetch(parsed.spec_url, {
        signal: AbortSignal.timeout(SPEC_FETCH_TIMEOUT_MS),
        headers: { Accept: "application/json, application/yaml, */*" },
      });
      if (!fetchRes.ok) {
        return res.status(400).json({ error: `Could not fetch spec: HTTP ${fetchRes.status} from ${parsed.spec_url}` });
      }
      const text = await fetchRes.text();
      if (text.length > MAX_SPEC_SIZE_BYTES) {
        return res.status(400).json({ error: `Spec exceeds ${MAX_SPEC_SIZE_BYTES / 1024 / 1024}MB size limit.` });
      }

      // Try parsing as JSON first; YAML support would need a dependency
      // this codebase doesn't carry, so we document JSON-only for now.
      try {
        specContent = JSON.parse(text);
      } catch {
        return res.status(400).json({
          error: "Could not parse spec as JSON. Paste the spec as JSON, or host a JSON version at the URL.",
        });
      }
    } catch (err) {
      return res.status(400).json({ error: `Could not fetch spec: ${(err as Error).message}` });
    }
  } else {
    specContent = parsed.spec_content;
  }

  // Validate the spec structure
  const detection = detectFormat(specContent);
  if ("error" in detection) {
    return res.status(400).json({ error: detection.error });
  }

  // Upsert: one spec per (owner, target_url). Importing again for the same
  // target replaces the previous spec rather than accumulating duplicates.
  const { data: existing } = await supabaseAdmin
    .from("api_specs")
    .select("id")
    .eq("owner", caller.ownerId)
    .eq("target_url", target_url)
    .maybeSingle();

  if (existing) {
    const { error } = await supabaseAdmin
      .from("api_specs")
      .update({
        spec_format: detection.format,
        spec_content: specContent,
        source_url: sourceUrl,
        updated_at: new Date().toISOString(),
      })
      .eq("id", existing.id);
    if (error) return res.status(500).json({ error: error.message });
  } else {
    const { error } = await supabaseAdmin
      .from("api_specs")
      .insert({
        owner: caller.ownerId,
        target_url,
        spec_format: detection.format,
        spec_content: specContent,
        source_url: sourceUrl,
      });
    if (error) return res.status(500).json({ error: error.message });
  }

  return res.status(200).json({
    ok: true,
    spec_format: detection.format,
    endpoint_count: detection.endpointCount,
  });
}
