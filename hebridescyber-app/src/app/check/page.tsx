import type { Metadata } from "next";
import InstantCheck from "@/components/InstantCheck";

export const metadata: Metadata = {
  title: "Free website security check — no signup — Hebrides Cyber",
  description: "Enter a web address and get an instant check of its HTTPS, security headers and email authentication. No account needed.",
};

export default async function CheckPage({ searchParams }: { searchParams: Promise<{ url?: string | string[] }> }) {
  const param = (await searchParams).url;
  // Only a plausible address is passed on; the API validates it properly.
  const initialUrl = typeof param === "string" && param.length <= 253 ? param.trim() : "";
  return (
    <div className="mx-auto max-w-2xl px-4 py-12">
      <h1 className="text-3xl font-bold">Free website security check</h1>
      <p className="mt-3 mb-8 text-cybertext/80">
        See how a site&apos;s HTTPS, security headers and email authentication look from the outside, in a few seconds, with no account. We only request the
        home page and look up DNS records, the same as a browser or mail server would.
      </p>
      <InstantCheck initialUrl={initialUrl} />
    </div>
  );
}
