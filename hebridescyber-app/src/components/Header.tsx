"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { supabase } from "@/lib/supabaseClient";
import { signOut } from "@/lib/auth";

export default function Header() {
  const router = useRouter();
  const [authed, setAuthed] = useState<boolean | null>(null); // null = not checked yet, avoids a sign-in/out flicker
  const [isAdmin, setIsAdmin] = useState(false);

  useEffect(() => {
    async function refresh(session: import("@supabase/supabase-js").Session | null) {
      setAuthed(Boolean(session));
      if (!session) {
        setIsAdmin(false);
        return;
      }
      const { data } = await supabase.from("users").select("is_admin").eq("id", session.user.id).maybeSingle();
      setIsAdmin(Boolean(data?.is_admin));
    }

    supabase.auth.getSession().then(({ data }) => refresh(data.session));
    const { data: subscription } = supabase.auth.onAuthStateChange((_event, session) => {
      refresh(session);
    });
    return () => subscription.subscription.unsubscribe();
  }, []);

  async function handleSignOut() {
    await signOut();
    router.push("/");
  }

  return (
    <header className="border-b border-cyberborder bg-cyberbg text-slatelight">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="font-mono text-lg font-bold tracking-tight text-white">
          <span className="text-neon">&gt;</span> Hebrides<span className="text-neon">_</span>Cyber
        </Link>
        <nav className="flex items-center gap-6 text-sm font-medium text-slatelight/80">
          <Link href="/services" className="hover:text-neon">Services</Link>
          <Link href="/pricing" className="hover:text-neon">Pricing</Link>
          <Link href="/blog" className="hover:text-neon">Blog</Link>
          <Link href="/contact" className="hover:text-neon">Contact</Link>
          {authed && (
            <Link href="/dashboard" className="hover:text-neon">
              Dashboard
            </Link>
          )}
          {authed && (
            <Link href="/account/security" className="text-slatelight/50 hover:text-neon">
              2FA
            </Link>
          )}
          {isAdmin && (
            <Link href="/admin" className="text-slatelight/50 hover:text-neon">
              Admin
            </Link>
          )}
          {authed === false && (
            <Link
              href="/login"
              className="rounded-md border border-neon/60 bg-neon/10 px-3 py-1.5 font-mono text-neon shadow-glowsm hover:bg-neon/20"
            >
              Sign in
            </Link>
          )}
          {authed === true && (
            <button onClick={handleSignOut} className="text-slatelight/50 hover:text-neon">
              Sign out
            </button>
          )}
        </nav>
      </div>
    </header>
  );
}
