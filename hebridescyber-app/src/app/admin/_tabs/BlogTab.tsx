"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { BlogPost, BlogPostFull, statusBadge, reltime, apiFetch, AdminInput, AdminTextarea, AdminSelect } from "../_shared";

export default function BlogTab({ token }: { token: string }) {
  const [posts, setPosts] = useState<BlogPost[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [editing, setEditing] = useState<BlogPostFull | null>(null);
  const [creating, setCreating] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    const params = new URLSearchParams();
    if (search) params.set("search", search);
    if (statusFilter) params.set("status", statusFilter);
    apiFetch<{ posts: BlogPost[] }>(`/api/admin/blog?${params}`, token)
      .then((d) => setPosts(d.posts))
      .finally(() => setLoading(false));
  }, [token, search, statusFilter]);

  useEffect(() => { load(); }, [load]);

  const openPost = async (slug: string) => {
    const post = await apiFetch<BlogPostFull>(`/api/admin/blog/${slug}`, token);
    setEditing(post);
  };

  const deletePost = async (slug: string) => {
    if (!confirm("Delete this post permanently?")) return;
    await apiFetch(`/api/admin/blog/${slug}`, token, { method: "DELETE" });
    load();
  };

  if (editing || creating) {
    return (
      <BlogEditor
        token={token}
        post={editing ?? undefined}
        onSave={() => { setEditing(null); setCreating(false); load(); }}
        onCancel={() => { setEditing(null); setCreating(false); }}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <AdminInput
          type="search"
          placeholder="Search posts…"
          className="flex-1 min-w-40"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <AdminSelect
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All</option>
          <option value="draft">Drafts</option>
          <option value="scheduled">Scheduled</option>
          <option value="published">Published</option>
        </AdminSelect>
        <button
          onClick={() => setCreating(true)}
          className="rounded-lg bg-neon px-4 py-2 text-sm font-medium text-cyberbg hover:opacity-90 transition-opacity shadow-glowsm"
        >
          + New post
        </button>
      </div>

      {loading ? (
        <p className="font-mono text-sm text-cybermuted">// loading…</p>
      ) : posts.length === 0 ? (
        <p className="font-mono text-sm text-cybermuted">// no posts found</p>
      ) : (
        <div className="rounded-xl border border-cyberborder bg-cyberpanel overflow-hidden">
          {posts.map((p) => (
            <div key={p.id} className="flex items-start gap-4 border-b border-cyberborder/50 px-4 py-4 last:border-0 hover:bg-cybertext/5 transition-colors">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <p className="font-medium text-cybertext">{p.title}</p>
                  {statusBadge(p.status)}
                </div>
                <p className="mt-0.5 text-xs text-cybermuted truncate">{p.excerpt || "No excerpt"}</p>
                <div className="mt-1 flex items-center gap-2 font-mono text-xs text-cybermuted">
                  <span>/{p.slug}</span>
                  <span>·</span>
                  <span>Updated {reltime(p.updated_at)}</span>
                  {p.status === "scheduled" && p.published_at && (
                    <>
                      <span>·</span>
                      <span className="text-seafoam">Publishes {new Date(p.published_at).toLocaleString()}</span>
                    </>
                  )}
                  {p.tags.length > 0 && (
                    <>
                      <span>·</span>
                      {p.tags.slice(0, 3).map((t) => (
                        <span key={t} className="rounded-sm border border-cyberborder px-1.5 py-0.5 text-neon/60">{t}</span>
                      ))}
                    </>
                  )}
                </div>
              </div>
              <div className="flex shrink-0 gap-1">
                <button onClick={() => openPost(p.slug)} className="rounded-sm border border-cyberborder px-2.5 py-1 text-xs text-cybertext/70 hover:border-neon hover:text-neon transition-colors">Edit</button>
                <button onClick={() => deletePost(p.slug)} className="rounded-sm bg-red-400/10 px-2.5 py-1 text-xs text-red-400 hover:bg-red-400/20 transition-colors">Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BlogEditor({
  token, post, onSave, onCancel,
}: {
  token: string;
  post?: BlogPostFull;
  onSave: () => void;
  onCancel: () => void;
}) {
  const [title, setTitle] = useState(post?.title ?? "");
  const [slug, setSlug] = useState(post?.slug ?? "");
  const [excerpt, setExcerpt] = useState(post?.excerpt ?? "");
  const [body, setBody] = useState(post?.body ?? "");
  const [tags, setTags] = useState((post?.tags ?? []).join(", "));
  const [status, setStatus] = useState<"draft" | "published" | "scheduled">(post?.status ?? "draft");
  // datetime-local wants "YYYY-MM-DDTHH:mm" in local time, not an ISO string.
  const toLocalInput = (iso: string | null) => {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const [publishAt, setPublishAt] = useState(post?.status === "scheduled" ? toLocalInput(post.published_at) : "");
  const [coverImageUrl, setCoverImageUrl] = useState(post?.cover_image_url ?? "");
  const [metaDescription, setMetaDescription] = useState(post?.meta_description ?? "");
  const [ogImage, setOgImage] = useState(post?.og_image ?? "");
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [slugError, setSlugError] = useState<string | null>(null);
  const [preview, setPreview] = useState(false);
  const [showSeo, setShowSeo] = useState(false);
  const [isDirty, setIsDirty] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const autoSlug = (t: string) =>
    t.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");

  const wordCount = body.trim().split(/\s+/).filter(Boolean).length;
  const readMins = Math.max(1, Math.round(wordCount / 200));

  useEffect(() => {
    const handler = (e: BeforeUnloadEvent) => {
      if (isDirty) { e.preventDefault(); e.returnValue = ""; }
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [isDirty]);

  const markDirty = () => setIsDirty(true);

  useEffect(() => {
    if (!slug || (post && slug === post.slug)) { setSlugError(null); return; }
    const t = setTimeout(async () => {
      try {
        const res = await fetch(`/api/admin/blog/${slug}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) setSlugError(`Slug "${slug}" is already taken.`);
        else setSlugError(null);
      } catch { setSlugError(null); }
    }, 600);
    return () => clearTimeout(t);
  }, [slug, post, token]);

  async function uploadImage(file: File) {
    setUploading(true);
    try {
      const reader = new FileReader();
      const dataUrl = await new Promise<string>((resolve, reject) => {
        reader.onload = () => resolve(reader.result as string);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
      const res = await apiFetch<{ url: string }>("/api/admin/blog/upload-image", token, {
        method: "POST",
        body: JSON.stringify({ dataUrl, filename: file.name }),
      });
      setCoverImageUrl(res.url);
      markDirty();
    } catch (e) {
      setError(`Image upload failed: ${(e as Error).message}`);
    } finally {
      setUploading(false);
    }
  }

  const save = async () => {
    if (slugError) { setError("Fix the slug conflict before saving."); return; }
    if (status === "scheduled" && (!publishAt || new Date(publishAt).getTime() <= Date.now())) {
      setError("Pick a future date/time to schedule this post.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const payload = {
        title, slug, excerpt, body,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
        status,
        ...(status === "scheduled" ? { published_at: new Date(publishAt).toISOString() } : {}),
        cover_image_url: coverImageUrl || null,
        meta_description: metaDescription || null,
        og_image: ogImage || null,
      };
      if (post) {
        await apiFetch(`/api/admin/blog/${post.slug}`, token, { method: "PATCH", body: JSON.stringify(payload) });
      } else {
        await apiFetch("/api/admin/blog", token, { method: "POST", body: JSON.stringify(payload) });
      }
      setIsDirty(false);
      onSave();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => { if (!isDirty || confirm("Discard unsaved changes?")) onCancel(); }}
          className="font-mono text-sm text-cybertext/50 hover:text-neon transition-colors"
        >
          ← back
        </button>
        <h2 className="text-lg font-semibold text-cybertext">{post ? "Edit post" : "New post"}</h2>
        {isDirty && <span className="font-mono text-xs text-amber-400">// unsaved changes</span>}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-cybermuted">{wordCount} words · {readMins} min read</span>
          <button
            onClick={() => setShowSeo((v) => !v)}
            className="rounded-sm border border-cyberborder px-3 py-1.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
          >
            SEO {showSeo ? "▲" : "▼"}
          </button>
          <button
            onClick={() => setPreview((v) => !v)}
            className="rounded-sm border border-cyberborder px-3 py-1.5 text-sm text-cybertext/60 hover:border-neon hover:text-neon transition-colors"
          >
            {preview ? "Edit" : "Preview"}
          </button>
          <AdminSelect
            value={status}
            onChange={(e) => { setStatus(e.target.value as "draft" | "published" | "scheduled"); markDirty(); }}
          >
            <option value="draft">Draft</option>
            <option value="scheduled">Schedule</option>
            <option value="published">Publish</option>
          </AdminSelect>
          {status === "scheduled" && (
            <input
              type="datetime-local"
              value={publishAt}
              min={toLocalInput(new Date().toISOString())}
              onChange={(e) => { setPublishAt(e.target.value); markDirty(); }}
              className="rounded-sm border border-cyberborder bg-cyberbg px-2 py-1.5 text-sm text-cybertext"
              aria-label="Publish at"
            />
          )}
          <button
            onClick={save}
            disabled={saving || !!slugError}
            className="rounded-lg bg-neon px-4 py-1.5 text-sm font-medium text-cyberbg hover:opacity-90 disabled:opacity-50 shadow-glowsm transition-opacity"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>

      {error && (
        <p className="rounded-sm border border-red-400/30 bg-red-400/10 px-3 py-2 text-sm text-red-400">{error}</p>
      )}

      {/* SEO panel */}
      {showSeo && (
        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-4 space-y-3">
          <h3 className="font-mono text-xs text-cybermuted uppercase tracking-wide">// SEO & Open Graph</h3>
          <div>
            <label className="mb-1 block font-mono text-xs text-cybermuted">Meta description (155 chars max)</label>
            <AdminTextarea
              value={metaDescription}
              onChange={(e) => { setMetaDescription(e.target.value); markDirty(); }}
              rows={2}
              maxLength={155}
              placeholder="Override the excerpt for search engines…"
              className="w-full"
            />
            <p className="text-right font-mono text-xs text-cybermuted">{metaDescription.length}/155</p>
          </div>
          <div>
            <label className="mb-1 block font-mono text-xs text-cybermuted">OG image URL (overrides cover image for social sharing)</label>
            <AdminInput
              type="url"
              value={ogImage}
              onChange={(e) => { setOgImage(e.target.value); markDirty(); }}
              placeholder="https://…"
              className="w-full"
            />
          </div>
        </div>
      )}

      {preview ? (
        <div className="prose prose-sm prose-invert max-w-none rounded-xl border border-cyberborder bg-cyberpanel p-6 prose-headings:text-neon prose-a:text-neon prose-code:bg-cyberbg prose-code:text-neon">
          {coverImageUrl && <img src={coverImageUrl} alt="" className="mb-6 w-full rounded-lg object-cover max-h-56" />}
          <h1>{title || "Untitled"}</h1>
          <p className="lead text-cybertext/60">{excerpt}</p>
          <div style={{ whiteSpace: "pre-wrap" }}>{body}</div>
        </div>
      ) : (
        <div className="grid gap-3">
          <AdminInput
            type="text"
            placeholder="Post title"
            value={title}
            onChange={(e) => {
              setTitle(e.target.value);
              if (!post) setSlug(autoSlug(e.target.value));
              markDirty();
            }}
            className="w-full text-lg font-semibold"
          />

          <div className="flex items-center gap-2">
            <span className="font-mono text-xs text-cybermuted shrink-0">Slug:</span>
            <input
              type="text"
              value={slug}
              onChange={(e) => { setSlug(e.target.value.toLowerCase().replace(/\s/g, "-")); markDirty(); }}
              className={`flex-1 rounded border bg-cyberbg px-2 py-1 font-mono text-xs text-cybertext focus:outline-hidden transition-colors ${
                slugError ? "border-red-400 focus:border-red-400" : "border-cyberborder focus:border-neon"
              }`}
            />
            {slugError && <span className="text-xs text-red-400">{slugError}</span>}
          </div>

          {/* Cover image */}
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-xs text-cybermuted">Cover image</span>
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
                className="rounded-sm border border-cyberborder px-2 py-0.5 text-xs text-cybertext/60 hover:border-neon hover:text-neon disabled:opacity-50 transition-colors"
              >
                {uploading ? "Uploading…" : "Upload"}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => { const f = e.target.files?.[0]; if (f) uploadImage(f); }}
              />
            </div>
            {coverImageUrl ? (
              <div className="relative inline-block">
                <img src={coverImageUrl} alt="Cover" className="h-24 rounded-lg object-cover border border-cyberborder" />
                <button
                  onClick={() => { setCoverImageUrl(""); markDirty(); }}
                  className="absolute -right-2 -top-2 rounded-full bg-cyberpanel border border-cyberborder px-1.5 py-0.5 text-xs text-red-400 hover:text-red-300"
                >
                  ✕
                </button>
              </div>
            ) : (
              <AdminInput
                type="url"
                placeholder="Or paste a URL…"
                value={coverImageUrl}
                onChange={(e) => { setCoverImageUrl(e.target.value); markDirty(); }}
                className="w-full"
              />
            )}
          </div>

          <AdminTextarea
            placeholder="Short excerpt (shown on listing page)…"
            value={excerpt}
            onChange={(e) => { setExcerpt(e.target.value); markDirty(); }}
            rows={2}
            className="w-full resize-y"
          />

          <AdminTextarea
            placeholder="Post body (Markdown supported)…"
            value={body}
            onChange={(e) => { setBody(e.target.value); markDirty(); }}
            rows={22}
            className="w-full resize-y font-mono"
          />

          <AdminInput
            type="text"
            placeholder="Tags (comma-separated: security, tls, headers)"
            value={tags}
            onChange={(e) => { setTags(e.target.value); markDirty(); }}
            className="w-full"
          />
        </div>
      )}
    </div>
  );
}
