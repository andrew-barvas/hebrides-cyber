import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-md px-6 py-32 text-center">
      <p className="mb-2 font-mono text-4xl font-bold text-neon/80">404</p>
      <h1 className="mb-4 text-2xl font-bold text-cybertext">Page not found</h1>
      <p className="text-sm text-cybermuted">
        That URL doesn&apos;t exist — it may have moved or been removed.
      </p>
      <div className="mt-8 flex justify-center gap-4">
        <Link
          href="/"
          className="rounded-md bg-neon px-5 py-2 text-sm font-semibold text-cyberbg hover:opacity-90"
        >
          Go home
        </Link>
        <Link
          href="/dashboard"
          className="rounded-md border border-cyberborder px-5 py-2 text-sm font-semibold text-cybertext hover:border-neon"
        >
          Dashboard
        </Link>
      </div>
    </div>
  );
}
