"use client";

import RouteError from "@/components/RouteError";

export default function AccountError(props: { error: Error & { digest?: string }; reset: () => void }) {
  return <RouteError {...props} section="the account" />;
}
