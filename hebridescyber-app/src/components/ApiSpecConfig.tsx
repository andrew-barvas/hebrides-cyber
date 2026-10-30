"use client";

import { useEffect, useState, useCallback } from "react";
import { supabase } from "@/lib/supabaseClient";

type ApiSpec = {
  id: string;
  target_url: string;
  spec_format: string;
  source_url: string | null;
  endpoint_count: number;
  created_at: string;
  updated_at: string;
};

type ImportMode = "url" | "paste";

export default function ApiSpecConfig() {
  const [specs, setSpecs] = useState<ApiSpec[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const [importMode, setImportMode] = useState<ImportMode>("url");
  const [targetUrl, setTargetUrl] = useState("");
  const [specUrl, setSpecUrl] = useState("");
  const [specJson, setSpecJson] = useState("");

  const loadSpecs = useCallback(async () => {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    const res = await fetch("/api/account/api-spec", {
      headers: { Authorization: `Bearer ${session.access_token}` },
    });
    if (res.ok) {
      const json = await res.json();
      setSpecs(json.specs ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadSpecs(); }, [loadSpecs]);

  function resetForm() {
    setTargetUrl("");
    setSpecUrl("");
    setSpecJson("");
    setImportMode("url");
  }

  async function importSpec(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    setMessage(null);

    const { data: { session } } = await supabase.auth.getSession();
    if (!session) { setSaving(false); return; }

    let body: Record<string, unknown>;
    if (importMode === "url") {
      body = { target_url: targetUrl, spec_url: specUrl };
    } else {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(specJson);
      } catch {
        setMessage("Invalid JSON. Paste a valid OpenAPI/Swagger spec as JSON.");
        setSaving(false);
        return;
      }
      body = { target_url: targetUrl, spec_content: parsed };
    }

    const res = await fetch("/api/account/api-spec", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    });

    if (res.ok) {
      const json = await res.json();
      setMessage(`Spec imported (${json.spec_format}, ${json.endpoint_count} endpoints).`);
      setShowForm(false);
      resetForm();
      loadSpecs();
    } else {
      const json = await res.json().catch(() => ({ error: "Failed to import spec" }));
      setMessage(json.error ?? "Failed to import spec");
    }
    setSaving(false);
  }

  async function deleteSpec(id: string) {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return;

    const res = await fetch("/api/account/api-spec", {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ id }),
    });

    if (res.ok) {
      setMessage("API spec removed.");
      loadSpecs();
    } else {
      const json = await res.json().catch(() => ({ error: "Failed to delete" }));
      setMessage(json.error ?? "Failed to delete");
    }
  }

  const formatLabel: Record<string, string> = {
    openapi3: "OpenAPI 3.x",
    openapi2: "OpenAPI 2.0",
    swagger: "Swagger",
  };

  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="font-mono text-sm font-semibold text-neon">API Spec Scanning</h3>
        <button
          onClick={() => { setShowForm(!showForm); resetForm(); setMessage(null); }}
          className="rounded-sm border border-neon/30 px-3 py-1 text-xs text-neon hover:bg-neon/10"
        >
          {showForm ? "Cancel" : "+ Import spec"}
        </button>
      </div>

      <p className="text-xs text-cybertext/50 mb-4">
        Import an OpenAPI or Swagger spec to enable spec-aware security testing. The scanner will
        test every documented endpoint for auth bypass, method confusion, schema violations,
        injection vulnerabilities, and excessive data exposure.
      </p>

      {message && (
        <div className="mb-3 rounded-sm border border-neon/30 bg-neon/5 px-3 py-2 text-xs text-neon">
          {message}
        </div>
      )}

      {showForm && (
        <form onSubmit={importSpec} className="mb-4 space-y-3 rounded-sm border border-cyberborder bg-cyberbg p-4">
          <div>
            <label className="block text-xs text-cybertext/60 mb-1">Target URL</label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://api.example.com"
              required
              className="w-full rounded-sm border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext"
            />
            <p className="mt-1 text-xs text-cybermuted">
              The base URL of the API this spec describes. Must match a monitored target.
            </p>
          </div>

          <div>
            <label className="block text-xs text-cybertext/60 mb-1">Import method</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-1.5 text-xs text-cybertext">
                <input
                  type="radio"
                  name="importMode"
                  value="url"
                  checked={importMode === "url"}
                  onChange={() => setImportMode("url")}
                  className="accent-neon"
                />
                Fetch from URL
              </label>
              <label className="flex items-center gap-1.5 text-xs text-cybertext">
                <input
                  type="radio"
                  name="importMode"
                  value="paste"
                  checked={importMode === "paste"}
                  onChange={() => setImportMode("paste")}
                  className="accent-neon"
                />
                Paste JSON
              </label>
            </div>
          </div>

          {importMode === "url" ? (
            <div>
              <label className="block text-xs text-cybertext/60 mb-1">Spec URL</label>
              <input
                type="url"
                value={specUrl}
                onChange={(e) => setSpecUrl(e.target.value)}
                placeholder="https://api.example.com/openapi.json"
                required
                className="w-full rounded-sm border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
              />
              <p className="mt-1 text-xs text-cybermuted">
                Must serve JSON. YAML is not currently supported.
              </p>
            </div>
          ) : (
            <div>
              <label className="block text-xs text-cybertext/60 mb-1">Spec JSON</label>
              <textarea
                value={specJson}
                onChange={(e) => setSpecJson(e.target.value)}
                placeholder='{"openapi": "3.0.0", "info": {...}, "paths": {...}}'
                required
                rows={8}
                className="w-full rounded-sm border border-cyberborder bg-cyberpanel px-3 py-1.5 text-sm text-cybertext font-mono"
              />
              <p className="mt-1 text-xs text-cybermuted">
                Paste the full OpenAPI/Swagger spec as a JSON object. Max 5MB.
              </p>
            </div>
          )}

          <button
            type="submit"
            disabled={saving}
            className="rounded-sm bg-neon px-4 py-1.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90 disabled:opacity-50"
          >
            {saving ? "Importing..." : "Import spec"}
          </button>
        </form>
      )}

      {loading ? (
        <p className="text-xs text-cybermuted">Loading...</p>
      ) : specs.length === 0 ? (
        <p className="text-xs text-cybermuted">
          No API specs imported. Import a spec to enable spec-aware endpoint testing during scans.
        </p>
      ) : (
        <ul className="space-y-2">
          {specs.map((spec) => (
            <li
              key={spec.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-sm border border-cyberborder bg-cyberbg px-3 py-2"
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-block rounded-sm bg-neon/10 px-2 py-0.5 text-xs font-mono text-neon">
                  {formatLabel[spec.spec_format] ?? spec.spec_format}
                </span>
                <span className="text-sm text-cybertext truncate max-w-[200px]" title={spec.target_url}>
                  {spec.target_url}
                </span>
                <span className="text-xs text-cybermuted">
                  {spec.endpoint_count} endpoint{spec.endpoint_count !== 1 ? "s" : ""}
                </span>
                {spec.source_url && (
                  <span className="text-xs text-cybermuted truncate max-w-[150px]" title={spec.source_url}>
                    via {new URL(spec.source_url).hostname}
                  </span>
                )}
                <span className="text-xs text-cybermuted">
                  Updated {new Date(spec.updated_at).toLocaleDateString()}
                </span>
              </div>
              <button
                onClick={() => deleteSpec(spec.id)}
                className="text-xs text-red-400 hover:text-red-300"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
