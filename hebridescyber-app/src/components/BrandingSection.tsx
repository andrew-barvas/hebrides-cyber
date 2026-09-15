"use client";

import { useCallback, useRef, useState } from "react";

type Props = {
  token: string;
  initialLogoUrl: string | null;
  initialBrandName: string | null;
};

const MAX_LOGO_BYTES = 5 * 1024 * 1024;

export default function BrandingSection({ token, initialLogoUrl, initialBrandName }: Props) {
  const [logoUrl, setLogoUrl] = useState<string | null>(initialLogoUrl);
  const [brandName, setBrandName] = useState(initialBrandName ?? "");
  const [uploading, setUploading] = useState(false);
  const [savingName, setSavingName] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const readFileAsDataUrl = (file: File): Promise<string> =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => reject(reader.error ?? new Error("Could not read file"));
      reader.readAsDataURL(file);
    });

  const handleFileChange = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      setError(null);
      setSaved(false);

      if (!file.type.startsWith("image/")) {
        setError("Logo must be an image file");
        return;
      }
      if (file.size > MAX_LOGO_BYTES) {
        setError("Logo must be under 5 MB");
        return;
      }

      setUploading(true);
      try {
        const dataUrl = await readFileAsDataUrl(file);
        const res = await fetch("/api/account/branding-logo", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
          body: JSON.stringify({ dataUrl, filename: file.name }),
        });
        const body = await res.json();
        if (!res.ok) throw new Error(body.error ?? "Could not upload logo");
        setLogoUrl(body.brand_logo_url ?? null);
        setSaved(true);
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setUploading(false);
        if (fileInputRef.current) fileInputRef.current.value = "";
      }
    },
    [token]
  );

  async function saveBrandName(e: React.FormEvent) {
    e.preventDefault();
    setSavingName(true);
    setError(null);
    setSaved(false);
    try {
      const res = await fetch("/api/account/branding-logo", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ brandName }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Could not save brand name");
      setBrandName(body.brand_name ?? "");
      setSaved(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSavingName(false);
    }
  }

  return (
    <section className="rounded-xl border border-cyberborder bg-cyberpanel p-5">
      <h2 className="mb-4 font-mono text-xs text-cybertext/40 uppercase tracking-wide">// white-label branding</h2>

      <p className="mb-4 text-xs text-cybertext/50 leading-relaxed">
        Agency plan: swap the default Hebrides Cyber header on generated PDF reports for your
        own logo and name. Leave both unset to keep the default template.
      </p>

      {error && <p className="mb-3 text-xs text-red-400" role="alert">{error}</p>}
      {saved && !error && <p className="mb-3 text-xs text-neon">Saved.</p>}

      <div className="mb-5 flex flex-wrap items-center gap-4">
        <div className="flex h-16 w-16 shrink-0 items-center justify-center overflow-hidden rounded-lg border border-cyberborder bg-cyberbg">
          {logoUrl ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img src={logoUrl} alt="Report logo preview" className="h-full w-full object-contain" />
          ) : (
            <span className="font-mono text-[10px] text-cybertext/30">no logo</span>
          )}
        </div>
        <div>
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleFileChange}
            disabled={uploading}
            className="block text-xs text-cybertext/60 file:mr-3 file:rounded-md file:border file:border-cyberborder file:bg-cyberbg file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-cybertext/70 hover:file:border-neon hover:file:text-neon file:transition-colors disabled:opacity-40"
          />
          <p className="mt-1 text-[11px] text-cybertext/30">PNG, JPG or SVG-as-raster, under 5 MB.</p>
        </div>
        {uploading && <span className="font-mono text-xs text-cybertext/40">uploading…</span>}
      </div>

      <form onSubmit={saveBrandName} className="flex flex-wrap gap-2">
        <input
          type="text"
          maxLength={80}
          value={brandName}
          onChange={(e) => setBrandName(e.target.value)}
          placeholder="Report brand name (e.g. Acme Security)"
          className="min-w-0 w-full sm:min-w-[240px] flex-1 rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
        />
        <button
          type="submit"
          disabled={savingName}
          className="rounded-md bg-neon px-4 py-2 text-sm font-semibold text-cyberbg shadow-glowsm hover:opacity-90 disabled:opacity-40 transition-opacity"
        >
          {savingName ? "Saving…" : "Save name"}
        </button>
      </form>
    </section>
  );
}
