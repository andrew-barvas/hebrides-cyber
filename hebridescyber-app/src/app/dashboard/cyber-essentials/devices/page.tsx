"use client";

import Link from "next/link";
import DeviceAgentDevices from "@/components/DeviceAgentDevices";
import PlanUpsell from "@/components/PlanUpsell";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";
import { planIncludes } from "@/lib/planAccess";
import { DEVICE_AGENT_TIER } from "@/lib/deviceAgent/access";

export default function DevicesPage() {
  const { accessToken, plan } = useAppSession();
  const allowed = planIncludes(plan, DEVICE_AGENT_TIER);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./cyber-essentials/devices"
        title="Device patching"
        description="Which of your devices miss the Cyber Essentials rule that high and critical security updates are installed within 14 days, from a small agent on each device. It reports the OS version, installed software and pending updates, and never scans your network."
        actions={
          <Link href="/dashboard/cyber-essentials" className="text-sm text-neon hover:underline">
            Cyber Essentials readiness
          </Link>
        }
      />
      {allowed ? <DeviceAgentDevices token={accessToken} /> : <PlanUpsell plan={plan} />}
    </div>
  );
}
