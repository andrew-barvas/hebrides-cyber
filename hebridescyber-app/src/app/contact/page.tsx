"use client";

import { useState } from "react";
import { TEAM_SIZE_OPTIONS, BUDGET_RANGE_OPTIONS } from "@/lib/contactOptions";

export default function ContactPage() {
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    const data = Object.fromEntries(new FormData(e.currentTarget));

    try {
      const res = await fetch("/api/contact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error ?? "Something went wrong — please try again.");
      setSubmitted(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  }

  if (submitted) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-cyberbg px-6 text-center">
        <p className="mb-4 font-mono text-sm text-neon" aria-hidden="true">// message received</p>
        <h1 className="text-2xl font-bold text-cybertext">Thanks!</h1>
        <p className="mt-4 max-w-sm text-cybertext/70">
          We&apos;ll be in touch within 24 hours to arrange your free Security Score scan.
        </p>
      </div>
    );
  }

  return (
    <div className="bg-cyberbg min-h-screen">
      {/* Hero */}
      <section className="relative overflow-hidden bg-cyberbg px-6 py-20 text-center">
        <div className="bg-grid pointer-events-none absolute inset-0 opacity-60" />
        <div className="relative">
          <p className="mb-3 font-mono text-sm text-neon" aria-hidden="true">
            <span className="text-cybertext/60">$</span> ./contact --get-started
          </p>
          <h1 className="text-4xl font-bold text-cybertext">Get in touch</h1>
          <p className="mx-auto mt-4 max-w-xl text-cybertext/70">
            Tell us about your site or app and we&apos;ll get back to you with next steps and a free Security Score scan.
          </p>
        </div>
      </section>

      <div className="mx-auto max-w-xl px-6 pb-20 pt-10">
        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            <Field label="Name" name="name" type="text" required />
            <Field label="Email" name="email" type="email" required />
            <Field label="Website / App URL" name="url" type="url" placeholder="https://your-site.com" />
            <Field label="Company / Organisation" name="company" type="text" />
            <SelectField label="Team size" name="teamSize" options={TEAM_SIZE_OPTIONS} />
            <SelectField label="Budget range" name="budgetRange" options={BUDGET_RANGE_OPTIONS} />
            <div>
              <label htmlFor="message" className="mb-1.5 block font-mono text-xs text-cybertext/60 uppercase tracking-wider">
                Message
              </label>
              <textarea
                id="message"
                name="message"
                rows={5}
                required
                minLength={10}
                className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
                placeholder="Tell us about your setup…"
              />
            </div>
            {error && (
              <p role="alert" className="rounded-md border border-red-400/30 bg-red-400/10 px-3 py-2 text-sm text-red-400">
                {error}
              </p>
            )}
            <button
              type="submit"
              disabled={submitting}
              className="w-full rounded-md bg-neon px-6 py-3 font-semibold text-cyberbg shadow-glow hover:opacity-90 disabled:opacity-50 transition-opacity"
            >
              {submitting ? "Sending…" : "Send message"}
            </button>
          </form>
        </div>

        {/* Trust signals */}
        <div className="mt-8 grid grid-cols-3 gap-4 text-center">
          {[
            { label: "Response time", value: "< 24 hrs" },
            { label: "First scan", value: "Free" },
            { label: "No commitment", value: "Required" },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-lg border border-cyberborder bg-cyberpanel p-4">
              <p className="font-mono text-sm font-bold text-neon">{value}</p>
              <p className="mt-0.5 text-xs text-cybertext/50">{label}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  name,
  type,
  required,
  placeholder,
}: {
  label: string;
  name: string;
  type: string;
  required?: boolean;
  placeholder?: string;
}) {
  return (
    <div>
      <label htmlFor={name} className="mb-1.5 block font-mono text-xs text-cybertext/60 uppercase tracking-wider">
        {label}
      </label>
      <input
        id={name}
        name={name}
        type={type}
        required={required}
        placeholder={placeholder}
        className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext placeholder-cybertext/30 focus:border-neon focus:outline-none transition-colors"
      />
    </div>
  );
}

function SelectField({
  label,
  name,
  options,
}: {
  label: string;
  name: string;
  options: ReadonlyArray<{ value: string; label: string }>;
}) {
  return (
    <div>
      <label htmlFor={name} className="mb-1.5 block font-mono text-xs text-cybertext/60 uppercase tracking-wider">
        {label} <span className="normal-case text-cybermuted">(optional)</span>
      </label>
      <select
        id={name}
        name={name}
        defaultValue=""
        className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-cybertext focus:border-neon focus:outline-none transition-colors"
      >
        <option value="">Select…</option>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}
