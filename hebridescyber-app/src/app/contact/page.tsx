"use client";

import { useState } from "react";

export default function ContactPage() {
  const [submitted, setSubmitted] = useState(false);

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.currentTarget));
    // TODO: replace with a real API call.
    console.log("Contact form submission (not yet wired to a backend):", data);
    setSubmitted(true);
  }

  if (submitted) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center bg-cyberbg px-6 text-center">
        <p className="mb-4 font-mono text-sm text-neon">// message received</p>
        <h1 className="text-2xl font-bold text-white">Thanks!</h1>
        <p className="mt-4 max-w-sm text-slatelight/70">
          We&apos;ll be in touch shortly to arrange your free Security Score scan.
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
          <p className="mb-3 font-mono text-sm text-neon">
            <span className="text-slatelight/40">$</span> ./contact --get-started
          </p>
          <h1 className="text-4xl font-bold text-white">Get in touch</h1>
          <p className="mx-auto mt-4 max-w-xl text-slatelight/70">
            Tell us about your site or app and we&apos;ll get back to you with next steps and a free Security Score scan.
          </p>
        </div>
      </section>

      <div className="mx-auto max-w-xl px-6 pb-20 pt-10">
        <div className="rounded-xl border border-cyberborder bg-cyberpanel p-8">
          <form onSubmit={handleSubmit} className="space-y-5">
            <Field label="Name" name="name" type="text" required />
            <Field label="Email" name="email" type="email" required />
            <Field label="Website / App URL" name="url" type="url" />
            <div>
              <label className="mb-1.5 block font-mono text-xs text-slatelight/60 uppercase tracking-wider">
                Message
              </label>
              <textarea
                name="message"
                rows={5}
                required
                className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-white placeholder-slatelight/30 focus:border-neon focus:outline-none transition-colors"
                placeholder="Tell us about your setup…"
              />
            </div>
            <button
              type="submit"
              className="w-full rounded-md bg-neon px-6 py-3 font-semibold text-cyberbg shadow-glow hover:opacity-90 transition-opacity"
            >
              Send message
            </button>
          </form>
        </div>

        {/* Trust signals */}
        <div className="mt-8 grid grid-cols-3 gap-4 text-center">
          {[
            { label: "Response time", value: "< 24 hours" },
            { label: "First scan", value: "Free" },
            { label: "No commitment", value: "Required" },
          ].map(({ label, value }) => (
            <div key={label} className="rounded-lg border border-cyberborder bg-cyberpanel p-4">
              <p className="font-mono text-sm font-bold text-neon">{value}</p>
              <p className="mt-0.5 text-xs text-slatelight/50">{label}</p>
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
}: {
  label: string;
  name: string;
  type: string;
  required?: boolean;
}) {
  return (
    <div>
      <label className="mb-1.5 block font-mono text-xs text-slatelight/60 uppercase tracking-wider">
        {label}
      </label>
      <input
        name={name}
        type={type}
        required={required}
        className="w-full rounded-md border border-cyberborder bg-cyberbg px-3 py-2 text-sm text-white placeholder-slatelight/30 focus:border-neon focus:outline-none transition-colors"
      />
    </div>
  );
}
