import type { Metadata } from "next";
import Link from "next/link";
import { CI_SCRIPT, CI_TEMPLATES, ciFileSha256, readCiFile } from "@/lib/ciTemplates";

// Built once at deploy time: the page shows the files exactly as /ci/<file>
// serves them, and their checksum.
export const dynamic = "force-static";

export const metadata: Metadata = {
  title: "CI/CD security scans: GitHub, GitLab, Jenkins, Azure DevOps, Bitbucket — Hebrides Cyber",
  description:
    "Scan your site from any CI pipeline and fail the build only on new findings. Templates for GitHub Actions, GitLab, Jenkins, Azure DevOps and Bitbucket.",
};

const SETTINGS: { name: string; desc: string }[] = [
  { name: "HEBRIDES_CYBER_API_KEY", desc: "Required. Your API key, stored as a secret CI variable." },
  { name: "HEBRIDES_TARGET_URL", desc: "Required. The site to scan; it must already be verified on your account." },
  { name: "HEBRIDES_FAIL_ON", desc: "critical, high (default), medium, low, or none to report without ever failing." },
  { name: "HEBRIDES_JUNIT_FILE", desc: "Optional. Also write a JUnit report here, so new findings show in your CI's test view." },
  { name: "HEBRIDES_RESULT_FILE", desc: "Where the full JSON result goes (default hebrides-scan.json)." },
  { name: "HEBRIDES_TIMEOUT_SECONDS", desc: "How long to wait for the scan (default 540)." },
];

const EXIT_CODES: { code: string; meaning: string }[] = [
  { code: "0", meaning: "Passed: no new, untriaged finding at or above the threshold (or the first scan of the site, which sets the baseline)." },
  { code: "1", meaning: "Blocked: the scan found new findings at or above the threshold that you haven't triaged." },
  { code: "2", meaning: "Could not scan: a missing setting, an unverified site, an API error, or a scan that failed or timed out. Treat it as a failure: a scan that didn't run is not a pass." },
];

function Code({ children }: { children: string }) {
  return <code className="rounded bg-cyberbg px-1 py-0.5 font-mono text-xs text-neon">{children}</code>;
}

export default function CiDocsPage() {
  const scriptSha = ciFileSha256(CI_SCRIPT);

  return (
    <div className="bg-cyberbg min-h-screen text-cybertext">
      <div className="relative overflow-hidden border-b border-cyberborder px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-40" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> sh ci/hebrides-scan.sh
          </p>
          <h1 className="mx-auto max-w-2xl text-4xl font-bold sm:text-5xl">Security scans in your CI pipeline</h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            Scan your site on every merge request or on a schedule, and fail the build only when a change introduces a new
            problem, never on the backlog you already know about. Templates for GitHub Actions, GitLab, Jenkins, Azure DevOps
            and Bitbucket.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-3">
            <a
              href={`/ci/${CI_SCRIPT}`}
              download
              className="rounded-md bg-neon px-6 py-2.5 text-sm font-semibold text-cyberbg shadow-glow hover:opacity-90"
            >
              Download the script
            </a>
            <Link
              href="/dashboard/integrations"
              className="rounded-md border border-cybertext/20 px-6 py-2.5 text-sm font-semibold text-cybertext hover:border-neon hover:text-neon"
            >
              Create an API key
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-4xl space-y-14 px-6 py-16">
        <section aria-labelledby="setup">
          <p className="mb-1 font-mono text-xs text-neon/60">// set up</p>
          <h2 id="setup" className="mb-4 text-2xl font-bold">Four steps</h2>
          <ol className="list-decimal space-y-3 pl-5 text-sm leading-relaxed text-cybertext/80">
            <li>
              <Link href="/dashboard/assets#domain-verification" className="text-neon hover:underline">
                Verify the site
              </Link>{" "}
              you will scan. A CI job can&apos;t answer a verification challenge, so the API only scans sites already verified on
              your account.
            </li>
            <li>
              <Link href="/dashboard/integrations" className="text-neon hover:underline">
                Create an API key
              </Link>{" "}
              and store it in your CI system as a secret variable named <Code>HEBRIDES_CYBER_API_KEY</Code>.
            </li>
            <li>
              Save{" "}
              <a href={`/ci/${CI_SCRIPT}`} download className="text-neon hover:underline">
                {CI_SCRIPT}
              </a>{" "}
              in your repository as <Code>ci/hebrides-scan.sh</Code>. Keeping a copy means a change to it reaches your pipeline
              only when you review and commit it. It needs <Code>sh</Code>, <Code>curl</Code> and <Code>jq</Code>.
              <span className="mt-1 block break-all font-mono text-xs text-cybertext/50">SHA-256: {scriptSha}</span>
            </li>
            <li>
              Add the template for your CI system below, and set <Code>HEBRIDES_TARGET_URL</Code> to your site.
            </li>
          </ol>
        </section>

        <section aria-labelledby="gate">
          <p className="mb-1 font-mono text-xs text-neon/60">// what fails the build</p>
          <h2 id="gate" className="mb-4 text-2xl font-bold">Only what the change introduced</h2>
          <p className="mb-4 text-sm leading-relaxed text-cybertext/70">
            Each scan is compared with the previous scan of the same site. The build fails only on findings that are{" "}
            <strong className="text-cybertext">new</strong>, at or above <Code>HEBRIDES_FAIL_ON</Code>, and{" "}
            <strong className="text-cybertext">not triaged</strong>. Anything you have accepted, marked as a false positive or
            snoozed (until the snooze ends) is listed but not counted. Gating on every finding would turn the pipeline red on
            its first run, and a check like that gets switched off the same day.
          </p>
          <div className="overflow-x-auto">
          <table className="w-full min-w-[480px] text-left text-sm">
            <caption className="sr-only">Exit codes</caption>
            <thead>
              <tr className="border-b border-cyberborder font-mono text-xs text-cybertext/50">
                <th scope="col" className="py-2 pr-4">Exit code</th>
                <th scope="col" className="py-2">Meaning</th>
              </tr>
            </thead>
            <tbody>
              {EXIT_CODES.map((e) => (
                <tr key={e.code} className="border-b border-cyberborder/60 align-top">
                  <td className="py-2 pr-4 font-mono text-neon">{e.code}</td>
                  <td className="py-2 text-cybertext/80">{e.meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </section>

        <section aria-labelledby="settings">
          <p className="mb-1 font-mono text-xs text-neon/60">// settings</p>
          <h2 id="settings" className="mb-4 text-2xl font-bold">Environment variables</h2>
          <dl className="space-y-3 text-sm">
            {SETTINGS.map((s) => (
              <div key={s.name}>
                <dt className="font-mono text-xs text-neon">{s.name}</dt>
                <dd className="text-cybertext/70">{s.desc}</dd>
              </div>
            ))}
          </dl>
        </section>

        <section aria-labelledby="templates">
          <p className="mb-1 font-mono text-xs text-neon/60">// templates</p>
          <h2 id="templates" className="mb-2 text-2xl font-bold">Your CI system</h2>
          <nav aria-label="CI systems" className="mb-8 flex flex-wrap gap-2 text-sm">
            {CI_TEMPLATES.map((t) => (
              <a key={t.id} href={`#${t.id}`} className="rounded-md border border-cyberborder px-3 py-1 hover:border-neon hover:text-neon">
                {t.name}
              </a>
            ))}
          </nav>
          <div className="space-y-10">
            {CI_TEMPLATES.map((t) => (
              <article key={t.id} id={t.id} aria-labelledby={`${t.id}-title`} className="scroll-mt-6 rounded-lg border border-cyberborder bg-cyberpanel p-5">
                <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
                  <h3 id={`${t.id}-title`} className="text-lg font-semibold">{t.name}</h3>
                  <a href={`/ci/${t.file}`} download className="font-mono text-xs text-neon hover:underline">
                    download {t.file}
                  </a>
                </div>
                <p className="mb-1 text-xs text-cybertext/60">
                  Save as <Code>{t.saveAs}</Code>
                </p>
                <p className="mb-3 text-xs text-cybertext/60">API key secret: {t.secret}</p>
                <pre className="overflow-x-auto rounded-md bg-cyberbg p-4 text-xs leading-relaxed text-cybertext/80">{readCiFile(t.file)}</pre>
              </article>
            ))}
          </div>
        </section>

        <p className="text-sm text-cybertext/60">
          Everything the script does goes through the public API: <Code>POST /api/v1/scans</Code> to queue a scan and{" "}
          <Code>GET /api/v1/scans/&#123;id&#125;</Code> to read the result. Results also go to any{" "}
          <Link href="/dashboard/integrations" className="text-neon hover:underline">
            webhook
          </Link>{" "}
          you have registered.
        </p>
      </div>
    </div>
  );
}
