// Shared building blocks for the product sub-sites (/lookout, /exploit; see
// src/lib/productSites.ts). Server components, theme tokens only, so both
// pages re-theme with the rest of the site. Links into the platform are
// absolute main-site URLs (mainSiteUrl) because the same markup is served on
// the product's own subdomain too.
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function SectionHeading({ id, overline, title, intro }: { id: string; overline: string; title: string; intro?: ReactNode }) {
  return (
    <div className="mb-8 max-w-3xl">
      <p className="mb-2 font-mono text-xs text-neon" aria-hidden="true">
        {"// "}
        {overline}
      </p>
      <h2 id={id} className="text-2xl font-bold sm:text-3xl">
        {title}
      </h2>
      {intro && <p className="mt-3 text-cybertext/70 leading-relaxed">{intro}</p>}
    </div>
  );
}

export function CtaLink({ href, children, variant = "primary" }: { href: string; children: ReactNode; variant?: "primary" | "secondary" }) {
  return (
    <a
      href={href}
      className={cn(
        "inline-flex items-center justify-center rounded-md px-6 py-2.5 text-sm font-semibold transition-colors",
        variant === "primary"
          ? "bg-neon text-cyberbg shadow-glow hover:opacity-90"
          : "border border-cybertext/20 text-cybertext hover:border-neon hover:text-neon"
      )}
    >
      {children}
    </a>
  );
}

/** In-page section links, sticky under the site header on wide screens and scrolling sideways on phones. */
export function SectionNav({ label, items }: { label: string; items: { href: string; label: string }[] }) {
  return (
    <nav aria-label={label} className="sticky top-0 z-20 border-b border-cyberborder bg-cyberbg/95 backdrop-blur">
      <ul className="mx-auto flex max-w-6xl gap-5 overflow-x-auto px-4 py-3 text-sm text-cybertext/70 sm:px-6">
        {items.map((item) => (
          <li key={item.href} className="shrink-0">
            <a href={item.href} className="hover:text-neon transition-colors">
              {item.label}
            </a>
          </li>
        ))}
      </ul>
    </nav>
  );
}

export function FeatureCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5">
      <h3 className="mb-2 font-semibold">{title}</h3>
      <div className="text-sm text-cybertext/70 leading-relaxed">{children}</div>
    </div>
  );
}

/** A browser-window frame for product mockups. Always labelled as example data. */
export function MockWindow({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <figure className={cn("overflow-hidden rounded-xl border border-cyberborder bg-cyberpanel shadow-glowsm", className)}>
      <div className="flex items-center gap-2 border-b border-cyberborder px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-cybertext/20" aria-hidden="true" />
        <span className="h-2.5 w-2.5 rounded-full bg-cybertext/20" aria-hidden="true" />
        <span className="h-2.5 w-2.5 rounded-full bg-cybertext/20" aria-hidden="true" />
        <span className="ml-2 truncate font-mono text-xs text-cybertext/60">{title}</span>
      </div>
      <div className="p-4 sm:p-5">{children}</div>
      <figcaption className="border-t border-cyberborder px-4 py-2 text-[11px] text-cybertext/50">Illustration with example data</figcaption>
    </figure>
  );
}

export function FaqList({ items }: { items: { q: string; a: ReactNode }[] }) {
  return (
    <div className="divide-y divide-cyberborder rounded-lg border border-cyberborder bg-cyberpanel">
      {items.map((item) => (
        <details key={item.q} className="group px-5 py-4">
          <summary className="cursor-pointer list-none font-semibold marker:hidden">
            <span className="mr-2 font-mono text-neon group-open:hidden" aria-hidden="true">+</span>
            <span className="mr-2 hidden font-mono text-neon group-open:inline" aria-hidden="true">−</span>
            {item.q}
          </summary>
          <div className="mt-3 text-sm text-cybertext/70 leading-relaxed">{item.a}</div>
        </details>
      ))}
    </div>
  );
}

export function Tick({ children }: { children: ReactNode }) {
  return (
    <li className="flex gap-2">
      <span className="text-neon" aria-hidden="true">→</span>
      <span>{children}</span>
    </li>
  );
}
