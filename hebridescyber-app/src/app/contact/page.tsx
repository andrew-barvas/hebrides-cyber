"use client";

import { useState } from "react";

// Simple contact form. TODO: wire onSubmit to a real backend — e.g. a
// Supabase table + email notification, or a serverless function that sends
// via SendGrid/Postmark. Currently just logs to console as a placeholder.
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
      <div className="mx-auto max-w-xl px-6 py-24 text-center">
        <h1 className="text-2xl font-bold text-atlantic">Thanks!</h1>
        <p className="mt-4 text-slatedark/80">
          We&apos;ll be in touch shortly to arrange your free Security Score
          scan.
        </p>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-xl px-6 py-16">
      <h1 className="mb-2 text-3xl font-bold text-atlantic">Contact</h1>
      <p className="mb-8 text-slatedark/80">
        Tell us about your site or app and we&apos;ll get back to you with
        next steps.
      </p>
      <form onSubmit={handleSubmit} className="space-y-4">
        <Field label="Name" name="name" type="text" required />
        <Field label="Email" name="email" type="email" required />
        <Field label="Website / App URL" name="url" type="url" />
        <div>
          <label className="mb-1 block text-sm font-medium">Message</label>
          <textarea
            name="message"
            rows={4}
            required
            className="w-full rounded-md border border-slate-300 p-2"
          />
        </div>
        <button
          type="submit"
          className="rounded-md bg-atlantic px-6 py-3 font-semibold text-white hover:opacity-90"
        >
          Send
        </button>
      </form>
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
      <label className="mb-1 block text-sm font-medium">{label}</label>
      <input
        name={name}
        type={type}
        required={required}
        className="w-full rounded-md border border-slate-300 p-2"
      />
    </div>
  );
}
