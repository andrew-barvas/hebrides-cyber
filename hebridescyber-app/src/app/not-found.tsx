import Link from "next/link";

export default function NotFound() {
  return (
    <div className="mx-auto max-w-md px-6 py-32 text-center">
      <p className="mb-2 font-mono text-4xl font-bold text-atlantic/20">404</p>
      <h1 className="mb-4 text-2xl font-bold text-atlantic">Page not found</h1>
      <p className="text-sm text-slatedark/70">
        That URL doesn&apos;t exist — it may have moved or been removed.
      </p>
      <div className="mt-8 flex justify-center gap-4">
        <Link
          href="/"
          className="rounded-md bg-atlantic px-5 py-2 text-sm font-semibold text-white hover:opacity-90"
        >
          Go home
        </Link>
        <Link
          href="/dashboard"
          className="rounded-md border border-slate-200 px-5 py-2 text-sm font-semibold text-slatedark hover:border-atlantic"
        >
          Dashboard
        </Link>
      </div>
    </div>
  );
}
