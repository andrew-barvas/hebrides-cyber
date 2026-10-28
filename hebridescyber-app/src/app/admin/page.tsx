"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { getSession } from "@/lib/auth";
import { useSessionToken } from "@/lib/useSessionToken";
import dynamic from "next/dynamic";
import { Skeleton } from "@/components/ui/skeleton";
import { Tab } from "./_shared";

// Each tab is its own chunk: the admin page used to ship all ten (≈1.9k lines)
// to open any one of them.
function TabLoading() {
  return (
    <div className="space-y-3" aria-busy="true">
      <Skeleton className="h-8 w-48" />
      <Skeleton className="h-40 w-full" />
    </div>
  );
}

const OverviewTab = dynamic(() => import("./_tabs/OverviewTab"), { loading: () => <TabLoading /> });
const CustomersTab = dynamic(() => import("./_tabs/CustomersTab"), { loading: () => <TabLoading /> });
const ScansTab = dynamic(() => import("./_tabs/ScansTab"), { loading: () => <TabLoading /> });
const QueueTab = dynamic(() => import("./_tabs/QueueTab"), { loading: () => <TabLoading /> });
const BlogTab = dynamic(() => import("./_tabs/BlogTab"), { loading: () => <TabLoading /> });
const AuditTab = dynamic(() => import("./_tabs/AuditTab"), { loading: () => <TabLoading /> });
const ToolsTab = dynamic(() => import("./_tabs/ToolsTab"), { loading: () => <TabLoading /> });
const DeletionRequestsTab = dynamic(() => import("./_tabs/GdprTab"), { loading: () => <TabLoading /> });
const EmailHealthTab = dynamic(() => import("./_tabs/EmailTab"), { loading: () => <TabLoading /> });
const ContactsTab = dynamic(() => import("./_tabs/ContactsTab"), { loading: () => <TabLoading /> });


export default function AdminPage() {
  const [authState, setAuthState] = useState<"loading" | "signed-out" | "unauthorized" | "ready">("loading");
  const [activeTab, setActiveTab] = useState<Tab>("overview");
  // Every tab below sends this as a bearer token. Held in a hook that tracks
  // onAuthStateChange rather than captured once from the mount-time session —
  // an admin leaving this page open past the one-hour token lifetime would
  // otherwise find every tab's requests failing with 401 while the page still
  // looked signed in.
  const token = useSessionToken();

  useEffect(() => {
    (async () => {
      const s = await getSession();
      if (!s) { setAuthState("signed-out"); return; }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      let res: Response;
      try {
        res = await fetch("/api/admin/metrics", {
          signal: controller.signal,
          headers: { Authorization: `Bearer ${s.access_token}` },
        });
      } catch {
        setAuthState("unauthorized");
        return;
      } finally {
        clearTimeout(timeout);
      }

      if (res.status === 403 || !res.ok) { setAuthState("unauthorized"); return; }

      setAuthState("ready");
    })().catch(() => setAuthState("unauthorized"));
  }, []);

  if (authState === "loading") {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center">
        <p className="font-mono text-sm text-cybermuted">// authenticating…</p>
      </div>
    );
  }

  if (authState === "signed-out") {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
        <div className="text-center">
          <p className="mb-3 font-mono text-sm text-neon">// access denied</p>
          <h1 className="text-2xl font-bold text-cybertext">Sign in required</h1>
          <Link href="/login" className="mt-6 inline-block text-neon underline">Sign in →</Link>
        </div>
      </div>
    );
  }

  if (authState === "unauthorized") {
    return (
      <div className="bg-cyberbg min-h-screen flex items-center justify-center px-6">
        <div className="max-w-md">
          <p className="mb-3 font-mono text-sm text-red-400">// 403 forbidden</p>
          <h1 className="text-2xl font-bold text-cybertext">Admin access required</h1>
          <div className="mt-4 space-y-2 text-sm text-cybertext/60">
            <p>Could not verify admin access. Common causes:</p>
            <ul className="list-disc pl-5 space-y-1 text-cybertext/50">
              <li>You&apos;re not signed in — <Link href="/login" className="text-neon underline">sign in first</Link></li>
              <li>Your account doesn&apos;t have <code className="font-mono bg-cyberpanel px-1 rounded text-neon">is_admin = true</code> in Supabase</li>
              <li><code className="font-mono bg-cyberpanel px-1 rounded text-neon">SUPABASE_SERVICE_ROLE_KEY</code> not set in Azure app settings</li>
              <li>API routes not deployed yet — wait for CI to finish</li>
            </ul>
          </div>
          <Link href="/dashboard" className="mt-6 inline-block text-neon underline">← Dashboard</Link>
        </div>
      </div>
    );
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: "overview",  label: "Overview" },
    { key: "customers", label: "Customers" },
    { key: "scans",     label: "Scans" },
    { key: "queue",     label: "Queue" },
    { key: "blog",      label: "Blog / CMS" },
    { key: "audit",     label: "Audit log" },
    { key: "tools",     label: "Tools" },
    { key: "gdpr",      label: "Erasure" },
    { key: "email",     label: "Email" },
    { key: "contacts",  label: "Contacts" },
  ];

  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Subtle grid overlay */}
      <div className="bg-grid pointer-events-none fixed inset-0 opacity-30" />

      <div className="relative mx-auto max-w-7xl px-4 py-8">
        {/* Header */}
        <div className="mb-6 flex items-baseline justify-between">
          <div>
            <p className="font-mono text-xs text-neon/50">$ sudo hebrides-cyber --admin</p>
            <h1 className="text-2xl font-bold text-cybertext">Admin</h1>
          </div>
          <Link href="/dashboard" className="font-mono text-sm text-cybermuted hover:text-neon transition-colors">← Dashboard</Link>
        </div>

        {/* Tabs — horizontally scrollable on narrow screens so the 10 tabs
            never widen the page past the viewport (the row scrolls within the
            screen edges via the -mx-4 px-4 bleed). */}
        <nav className="mb-6 -mx-4 flex gap-1 overflow-x-auto whitespace-nowrap border-b border-cyberborder px-4">
          {tabs.map((t) => (
            <button
              key={t.key}
              onClick={() => setActiveTab(t.key)}
              className={`shrink-0 px-4 py-2 text-sm font-medium transition-colors ${
                activeTab === t.key
                  ? "border-b-2 border-neon text-neon"
                  : "text-cybermuted hover:text-cybertext"
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        {token && (
          <>
            {activeTab === "overview"  && <OverviewTab  token={token} />}
            {activeTab === "customers" && <CustomersTab token={token} />}
            {activeTab === "scans"     && <ScansTab     token={token} />}
            {activeTab === "queue"     && <QueueTab     token={token} />}
            {activeTab === "blog"      && <BlogTab      token={token} />}
            {activeTab === "audit"     && <AuditTab     token={token} />}
            {activeTab === "tools"     && <ToolsTab     token={token} />}
            {activeTab === "gdpr"      && <DeletionRequestsTab token={token} />}
            {activeTab === "email"     && <EmailHealthTab token={token} />}
            {activeTab === "contacts"  && <ContactsTab  token={token} />}
          </>
        )}
      </div>
    </div>
  );
}
