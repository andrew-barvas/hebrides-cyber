import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "SBOM Generation — Software Bill of Materials — Hebrides Cyber",
  description:
    "CycloneDX 1.5 Software Bills of Materials built from your lockfiles, transitive dependencies included, with known vulnerabilities from OSV.dev.",
};

type Feature = {
  icon: string;
  title: string;
  body: string;
};

const features: Feature[] = [
  {
    icon: "📋",
    title: "CycloneDX 1.5 standard",
    body: "Industry-standard SBOM format accepted by regulators, auditors, and supply chain security tools. Machine-readable JSON with full component and vulnerability correlation.",
  },
  {
    icon: "📦",
    title: "Every package, transitive ones included",
    body: "Read from your connected GitHub repository's lockfiles: npm, pnpm, Yarn, Poetry, Pipenv, Composer, Go, Gradle, Bundler, Cargo and NuGet, with exact versions and the chain that pulled each package in. Manifests (package.json, requirements.txt, composer.json, go.mod, pom.xml) are used where there is no lockfile.",
  },
  {
    icon: "🔍",
    title: "Vulnerability-enriched",
    body: "Every component is checked against OSV.dev for known CVEs. Your SBOM includes not just what you ship, but what's vulnerable — the combination auditors actually need.",
  },
  {
    icon: "🇪🇺",
    title: "EU Cyber Resilience Act ready",
    body: "The CRA (effective 2027) requires manufacturers to provide SBOMs for products with digital elements. Start generating them now, before the deadline.",
  },
  {
    icon: "🔗",
    title: "API-accessible",
    body: "GET /api/v1/scans/{id}/sbom returns a standards-compliant CycloneDX document. Integrate with your CI pipeline, compliance tooling, or supply chain management platform.",
  },
  {
    icon: "🔄",
    title: "Updated every scan",
    body: "Each scan regenerates the SBOM from current dependency data. No stale manifests — your bill of materials is always as fresh as your last security scan.",
  },
];

function FeatureCard({ feature }: { feature: Feature }) {
  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm">
      <div className="mb-3 flex items-start gap-3">
        <span className="text-xl flex-shrink-0 mt-0.5">{feature.icon}</span>
        <div>
          <h3 className="font-mono text-sm font-semibold text-neon leading-snug">{feature.title}</h3>
          <p className="mt-1.5 text-sm text-cybertext/70 leading-relaxed">{feature.body}</p>
        </div>
      </div>
    </div>
  );
}

export default function SbomPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> curl /api/v1/scans/latest/sbom {">"} sbom.cdx.json
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">
            Software Bill of Materials
          </h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            Know exactly what&apos;s in your software supply chain. CycloneDX 1.5 SBOMs generated
            automatically from your lockfiles, enriched with real vulnerability data.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Generate your SBOM
            </Link>
            <Link
              href="/pricing"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              View pricing
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-4xl px-6 py-16">
        <div className="mb-8">
          <p className="mb-1 font-mono text-xs text-neon/60">// what is an SBOM?</p>
          <p className="text-sm text-cybertext/60 leading-relaxed">
            A Software Bill of Materials is a complete inventory of every third-party component in
            your application — libraries, frameworks, and their versions. It&apos;s the software
            equivalent of an ingredients list, and regulators are starting to require it. The EU Cyber
            Resilience Act (CRA), effective 2027, mandates SBOMs for products with digital elements
            sold in the European market.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          {features.map((f) => (
            <FeatureCard key={f.title} feature={f} />
          ))}
        </div>

        <div className="mt-12 rounded-lg border border-cyberborder bg-cyberpanel p-6">
          <p className="mb-2 font-mono text-xs text-neon/60">// example output</p>
          <pre className="overflow-x-auto rounded-md bg-cyberbg p-4 text-xs text-cybertext/70 leading-relaxed">
{`{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2024-29041",
      "source": { "name": "OSV.dev" },
      "affects": [{ "ref": "npm:express@4.18.2" }]
    }
  ]
}`}
          </pre>
        </div>

        <div className="mt-16 rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// get started</p>
          <h2 className="mb-2 text-2xl font-bold">Generate your first SBOM today</h2>
          <p className="mb-6 text-cybertext/70">
            Connect your GitHub repository, run a scan, and download a CycloneDX 1.5 SBOM —
            all from one platform, no extra tooling required.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Get started free
            </Link>
            <Link
              href="/contact"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              Ask a question
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
