import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "AI-Driven Cyber Threats — Hebrides Cyber",
  description:
    "Autonomous AI agents are now hacking SMEs for as little as $25 per target. Learn how AI-powered attacks work and how automated security scanning defends against them.",
};

type ThreatFact = {
  stat: string;
  label: string;
  detail: string;
};

const threatFacts: ThreatFact[] = [
  {
    stat: "$25",
    label: "Average cost to compromise one business",
    detail:
      "The documented campaign spent $12k–18k in LLM API fees across all targets. With 27+ companies breached, the per-target cost was lower than a meal out.",
  },
  {
    stat: "600k+",
    label: "Payment card records stolen",
    detail:
      "Online retailers and SMEs with web-facing payment flows were the primary targets. The attackers harvested card data at industrial scale.",
  },
  {
    stat: "1,951",
    label: "Commands typed by the human operator",
    detail:
      "The AI agents did the rest. One person orchestrated the entire campaign across 260 sessions, mostly short instructions. The agents reasoned, planned, and executed autonomously.",
  },
  {
    stat: "633 hrs",
    label: "Of autonomous scanning in one week",
    detail:
      "146 deep-mode scans against 138 hosts. The agents ran in parallel, 24 hours a day, finding vulnerabilities faster than any human team could.",
  },
];

type DefencePoint = {
  icon: string;
  title: string;
  description: string;
};

const defencePoints: DefencePoint[] = [
  {
    icon: "🔍",
    title: "Same vulnerability classes, detected first",
    description:
      "AI attack agents exploit OWASP Top 10 vulnerabilities: injection, XSS, SSRF, authentication bypass, exposed endpoints. Our scan suite covers all of these with 25+ automated checks, finding them before attackers do.",
  },
  {
    icon: "🛡️",
    title: "Header and configuration hardening",
    description:
      "Missing security headers (CSP, HSTS, X-Frame-Options) and misconfigured CORS policies are low-hanging fruit for automated agents. Every scan checks and grades these.",
  },
  {
    icon: "📦",
    title: "Outdated library and dependency detection",
    description:
      "Attack agents chain known CVEs in outdated JavaScript libraries, npm packages, and CMS plugins. Our scans fingerprint every detected technology and cross-reference against real vulnerability databases.",
  },
  {
    icon: "🔑",
    title: "Exposed secrets and configuration files",
    description:
      "Forgotten .env files, exposed git repositories, database backups, and debug endpoints are exactly what autonomous agents search for. We probe for 20+ common exposure patterns on every scan.",
  },
  {
    icon: "📧",
    title: "Email authentication (SPF, DKIM, DMARC)",
    description:
      "AI agents can automate phishing campaigns using spoofed emails. Proper SPF, DKIM, and DMARC configuration prevents domain impersonation. We check all three on every scan.",
  },
  {
    icon: "☁️",
    title: "Cloud posture and public storage",
    description:
      "Publicly accessible S3 buckets and Azure storage containers are trivial for automated tools to discover and exfiltrate. Our cloud posture scans catch these misconfigurations.",
  },
];

function StatCard({ fact }: { fact: ThreatFact }) {
  return (
    <div className="rounded-lg border border-cyberborder bg-cyberpanel p-5 text-center">
      <p className="text-3xl font-bold text-neon">{fact.stat}</p>
      <p className="mt-1 text-sm font-semibold text-cybertext">{fact.label}</p>
      <p className="mt-2 text-xs text-cybertext/60 leading-relaxed">{fact.detail}</p>
    </div>
  );
}

function DefenceCard({ point }: { point: DefencePoint }) {
  return (
    <div className="group rounded-lg border border-cyberborder bg-cyberpanel p-5 transition duration-200 hover:border-neon/50 hover:shadow-glowsm">
      <div className="flex items-start gap-3">
        <span className="text-xl shrink-0 mt-0.5">{point.icon}</span>
        <div>
          <h3 className="font-mono text-sm font-semibold text-neon">{point.title}</h3>
          <p className="mt-1.5 text-sm text-cybertext/70 leading-relaxed">{point.description}</p>
        </div>
      </div>
    </div>
  );
}

export default function AiThreatsPage() {
  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      {/* Hero */}
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> alert --level=critical --source=ai-agent-campaign
          </p>
          <h1 className="mx-auto max-w-3xl text-4xl font-bold sm:text-5xl">
            AI agents are now hacking businesses for $25 each
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-cybertext/70">
            In 2026, autonomous AI tools were chained together to compromise 27+ companies and steal
            over 600,000 payment card records. The entire campaign cost less than $18,000 in AI
            compute. Your business is a target. Here&apos;s what you can do about it.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run a free scan
            </Link>
            <Link
              href="/what-we-check"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              See what we check
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-4xl px-6 py-16">
        {/* The campaign */}
        <section className="mb-16">
          <p className="mb-1 font-mono text-xs text-neon/60">// the documented attack campaign</p>
          <h2 className="mb-4 text-2xl font-bold">What happened</h2>
          <p className="text-sm text-cybertext/70 leading-relaxed mb-6">
            Between July and September 2026, a threat actor used three open-source AI agent tools
            &mdash; Strix for vulnerability discovery, Cairn for autonomous exploitation, and Hermes
            for orchestration &mdash; to systematically breach online retailers and small businesses.
            The campaign was documented by Palo Alto Unit 42, Gambit Security, BleepingComputer, and
            SecurityWeek. It is reportedly still active.
          </p>

          <div className="grid gap-4 sm:grid-cols-2">
            {threatFacts.map((f) => (
              <StatCard key={f.stat} fact={f} />
            ))}
          </div>
        </section>

        {/* How it works */}
        <section className="mb-16">
          <p className="mb-1 font-mono text-xs text-neon/60">// how autonomous AI attacks work</p>
          <h2 className="mb-4 text-2xl font-bold">The AI attack chain</h2>
          <div className="space-y-4">
            <div className="flex gap-4 items-start">
              <span className="shrink-0 w-8 h-8 rounded-full bg-neon/10 border border-neon/30 flex items-center justify-center text-neon text-sm font-bold">1</span>
              <div>
                <p className="text-sm font-semibold text-cybertext">Reconnaissance</p>
                <p className="text-sm text-cybertext/70">AI agents scan your website, identify technologies, find exposed endpoints, and map your attack surface &mdash; automatically, in minutes.</p>
              </div>
            </div>
            <div className="flex gap-4 items-start">
              <span className="shrink-0 w-8 h-8 rounded-full bg-neon/10 border border-neon/30 flex items-center justify-center text-neon text-sm font-bold">2</span>
              <div>
                <p className="text-sm font-semibold text-cybertext">Vulnerability discovery</p>
                <p className="text-sm text-cybertext/70">The agents test for injection, XSS, authentication bypass, exposed APIs, outdated libraries with known CVEs, and misconfigured security headers.</p>
              </div>
            </div>
            <div className="flex gap-4 items-start">
              <span className="shrink-0 w-8 h-8 rounded-full bg-neon/10 border border-neon/30 flex items-center justify-center text-neon text-sm font-bold">3</span>
              <div>
                <p className="text-sm font-semibold text-cybertext">Exploitation</p>
                <p className="text-sm text-cybertext/70">Once a vulnerability is found, the AI chains it with other weaknesses to gain access &mdash; installing payment skimmers, extracting databases, or establishing persistent backdoors.</p>
              </div>
            </div>
            <div className="flex gap-4 items-start">
              <span className="shrink-0 w-8 h-8 rounded-full bg-neon/10 border border-neon/30 flex items-center justify-center text-neon text-sm font-bold">4</span>
              <div>
                <p className="text-sm font-semibold text-cybertext">Data theft</p>
                <p className="text-sm text-cybertext/70">Payment card details, customer records, and credentials are extracted and sold. The tools run 24/7, targeting hundreds of businesses in parallel.</p>
              </div>
            </div>
          </div>
        </section>

        {/* What we detect */}
        <section className="mb-16">
          <p className="mb-1 font-mono text-xs text-neon/60">// how automated scanning defends you</p>
          <h2 className="mb-4 text-2xl font-bold">What our scans catch</h2>
          <p className="text-sm text-cybertext/70 leading-relaxed mb-6">
            Every vulnerability class that AI attack agents exploit is covered by our automated
            Security Score scan. We find the same weaknesses &mdash; before the attackers do.
          </p>

          <div className="grid gap-4 sm:grid-cols-2">
            {defencePoints.map((p) => (
              <DefenceCard key={p.title} point={p} />
            ))}
          </div>
        </section>

        {/* CTA */}
        <div className="rounded-xl border border-neon/30 bg-cyberpanel p-8 text-center">
          <p className="mb-1 font-mono text-xs text-neon/60">// don&apos;t wait for the attackers</p>
          <h2 className="mb-2 text-2xl font-bold">Find out what an AI agent would find on your site</h2>
          <p className="mb-6 text-cybertext/70">
            Free automated scan, one-page report, no commitment. If an attacker can compromise your
            business for $25, knowing your vulnerabilities first is the best investment you can make.
          </p>
          <div className="flex flex-wrap justify-center gap-3">
            <Link
              href="/dashboard"
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Run a free scan
            </Link>
            <Link
              href="/contact"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              Ask a question first
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
