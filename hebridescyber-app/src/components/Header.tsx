"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { supabase } from "@/lib/supabaseClient";
import { signOut } from "@/lib/auth";

function ThemeToggle() {
  const [dark, setDark] = useState(true);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
  }, []);

  function toggle() {
    const next = !dark;
    setDark(next);
    if (next) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("hc-theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("hc-theme", "light");
    }
  }

  return (
    <button
      onClick={toggle}
      aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
      className="flex items-center justify-center w-10 h-10 rounded-md border border-cyberborder text-slatelight/70 hover:text-neon hover:border-neon/50 transition-colors font-mono text-sm"
      title={dark ? "Light mode" : "Dark mode"}
    >
      {dark ? "☀" : "◑"}
    </button>
  );
}

export default function Header() {
  const router = useRouter();
  const pathname = usePathname();
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const drawerRef = useRef<HTMLDivElement>(null);

  // Close mobile menu on route change
  useEffect(() => { setMenuOpen(false); }, [pathname]);

  // Close on outside click
  useEffect(() => {
    if (!menuOpen) return;
    function handler(e: MouseEvent) {
      if (drawerRef.current && !drawerRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [menuOpen]);

  useEffect(() => {
    async function refresh(session: import("@supabase/supabase-js").Session | null) {
      setAuthed(Boolean(session));
      if (!session) { setIsAdmin(false); return; }
      const { data } = await supabase.from("users").select("is_admin").eq("id", session.user.id).maybeSingle();
      setIsAdmin(Boolean(data?.is_admin));
    }
    supabase.auth.getSession().then(({ data }) => refresh(data.session));
    const { data: subscription } = supabase.auth.onAuthStateChange((_event, session) => refresh(session));
    return () => subscription.subscription.unsubscribe();
  }, []);

  async function handleSignOut() {
    await signOut();
    setMenuOpen(false);
    router.push("/");
  }

  const navItems = [
    { href: "/services", label: "Services" },
    { href: "/pricing",  label: "Pricing" },
    { href: "/blog",     label: "Blog" },
    { href: "/contact",  label: "Contact" },
  ];

  return (
    <header className="border-b border-cyberborder bg-cyberbg text-slatelight" ref={drawerRef}>
      <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3 sm:px-6 sm:py-4">
        {/* Logo */}
        <Link
          href="/"
          className="font-mono text-base font-bold tracking-tight text-white sm:text-lg"
        >
          <span className="text-neon" aria-hidden="true">&gt;</span>{" "}
          Hebrides<span className="text-neon" aria-hidden="true">_</span>Cyber
        </Link>

        {/* Desktop nav */}
        <nav
          aria-label="Main navigation"
          className="hidden md:flex items-center gap-5 text-sm font-medium text-slatelight/80"
        >
          {navItems.map(({ href, label }) => (
            <Link key={href} href={href} className="py-1 hover:text-neon transition-colors">
              {label}
            </Link>
          ))}
          {authed && (
            <Link href="/dashboard" className="py-1 hover:text-neon transition-colors">
              Dashboard
            </Link>
          )}
          {authed && (
            <Link href="/account/security" className="py-1 text-slatelight/60 hover:text-neon transition-colors">
              2FA
            </Link>
          )}
          {isAdmin && (
            <Link href="/admin" className="py-1 text-slatelight/60 hover:text-neon transition-colors">
              Admin
            </Link>
          )}
          {authed === false && (
            <Link
              href="/login"
              className="rounded-md border border-neon/60 bg-neon/10 px-3 py-2 font-mono text-sm text-neon shadow-glowsm hover:bg-neon/20 transition-colors"
            >
              Sign in
            </Link>
          )}
          {authed === true && (
            <button
              onClick={handleSignOut}
              className="py-1 text-slatelight/60 hover:text-neon transition-colors"
            >
              Sign out
            </button>
          )}
          <ThemeToggle />
        </nav>

        {/* Mobile: always-visible controls */}
        <div className="flex items-center gap-2 md:hidden">
          <ThemeToggle />
          <button
            onClick={() => setMenuOpen((v) => !v)}
            aria-label={menuOpen ? "Close navigation menu" : "Open navigation menu"}
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            className="flex items-center justify-center w-10 h-10 rounded-md border border-cyberborder text-slatelight/70 hover:text-neon hover:border-neon/50 transition-colors font-mono text-base"
          >
            {menuOpen ? "✕" : "☰"}
          </button>
        </div>
      </div>

      {/* Mobile nav drawer */}
      {menuOpen && (
        <nav
          id="mobile-nav"
          aria-label="Mobile navigation"
          className="md:hidden border-t border-cyberborder bg-cyberbg"
        >
          <div className="mx-auto max-w-6xl px-4 py-2">
            {navItems.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className="flex items-center px-2 py-3.5 text-base font-medium text-slatelight/80 hover:text-neon border-b border-cyberborder/50 last:border-0 transition-colors"
              >
                {label}
              </Link>
            ))}
            {authed && (
              <Link
                href="/dashboard"
                className="flex items-center px-2 py-3.5 text-base font-medium text-slatelight/80 hover:text-neon border-b border-cyberborder/50 transition-colors"
              >
                Dashboard
              </Link>
            )}
            {authed && (
              <Link
                href="/account/security"
                className="flex items-center px-2 py-3.5 text-base font-medium text-slatelight/60 hover:text-neon border-b border-cyberborder/50 transition-colors"
              >
                Two-factor auth
              </Link>
            )}
            {isAdmin && (
              <Link
                href="/admin"
                className="flex items-center px-2 py-3.5 text-base font-medium text-slatelight/60 hover:text-neon border-b border-cyberborder/50 transition-colors"
              >
                Admin
              </Link>
            )}
            {authed === false && (
              <div className="py-3">
                <Link
                  href="/login"
                  className="block w-full rounded-md border border-neon/60 bg-neon/10 px-4 py-3 text-center font-mono text-base text-neon hover:bg-neon/20 transition-colors"
                >
                  Sign in
                </Link>
              </div>
            )}
            {authed === true && (
              <button
                onClick={handleSignOut}
                className="flex w-full items-center px-2 py-3.5 text-base font-medium text-slatelight/60 hover:text-neon transition-colors"
              >
                Sign out
              </button>
            )}
          </div>
        </nav>
      )}
    </header>
  );
}
