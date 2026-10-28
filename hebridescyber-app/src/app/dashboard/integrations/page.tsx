"use client";

// Every "connect Hebrides Cyber to something else" setting in one place.
// These used to be split between the dashboard (Slack, Teams, email prefs,
// scheduled reports, cloud credentials) and the account page (webhooks, API
// keys, repo, API spec, Jira/Linear, on-call) with no rule for which went
// where. Plan-gated items render a LockedFeature instead of disappearing.

import ApiKeys from "@/components/ApiKeys";
import ApiSpecConfig from "@/components/ApiSpecConfig";
import ChannelWebhookIntegration from "@/components/ChannelWebhookIntegration";
import CloudCredentialsConfig from "@/components/CloudCredentialsConfig";
import ConnectRepo from "@/components/ConnectRepo";
import LockedFeature from "@/components/LockedFeature";
import { planIncludes } from "@/lib/planAccess";
import NotificationPrefsSection from "@/components/NotificationPrefsSection";
import OncallIntegrationConfig from "@/components/OncallIntegrationConfig";
import ScheduledReportsConfig from "@/components/ScheduledReportsConfig";
import TicketIntegration from "@/components/TicketIntegration";
import UptimeMonitoringConfig from "@/components/UptimeMonitoringConfig";
import Webhooks from "@/components/Webhooks";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";

function Group({ id, title, description, children }: { id: string; title: string; description: string; children: React.ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-heading`} className="scroll-mt-6 space-y-4">
      <div className="border-b border-cyberborder pb-3">
        <h2 id={`${id}-heading`} className="text-lg font-semibold text-cybertext">
          {title}
        </h2>
        <p className="mt-0.5 text-sm text-cybermuted">{description}</p>
      </div>
      <div className="space-y-4">{children}</div>
    </section>
  );
}

export default function IntegrationsPage() {
  const { plan, accessToken } = useAppSession();
  const paid = plan !== "none";
  const chatAlerts = planIncludes(plan, "pro");

  return (
    <div className="space-y-10">
      <PageHeader
        eyebrow="$ ./integrations"
        title="Integrations"
        description="Route findings to where your team already works — chat, on-call, ticketing, code and cloud."
      />

      <Group id="alerts" title="Alerts & notifications" description="Where scan results and new findings get sent.">
        {chatAlerts ? (
          <>
            <ChannelWebhookIntegration provider="slack" />
            <ChannelWebhookIntegration provider="teams" />
          </>
        ) : (
          <LockedFeature
            title="slack & microsoft teams alerts"
            description="Post scan results and new-finding alerts straight into a Slack or Teams channel."
            availableOn="Pro & Agency"
          />
        )}
        {paid ? (
          <NotificationPrefsSection />
        ) : (
          <LockedFeature
            title="email notifications"
            description="Get an email when a scan completes, with thresholds so you only hear about scans that need attention."
            availableOn="Paid plans"
          />
        )}
        <OncallIntegrationConfig />
        {chatAlerts ? (
          <UptimeMonitoringConfig />
        ) : (
          <LockedFeature
            title="uptime monitoring"
            description="Connect your own UptimeRobot account to watch your verified sites and get a message here, in Slack or by email when one goes down."
            availableOn="Pro & Agency"
          />
        )}
        <Webhooks token={accessToken} />
      </Group>

      <Group id="ticketing" title="Ticketing" description="Turn findings into issues in the tracker your team already uses.">
        <TicketIntegration />
      </Group>

      <Group id="code" title="Code & API" description="Scan dependencies and API specs, or drive Hebrides Cyber from your own tooling.">
        <ConnectRepo />
        <ApiSpecConfig />
        <ApiKeys token={accessToken} />
      </Group>

      <Group id="cloud" title="Cloud & reporting" description="Posture checks on your cloud accounts, and security summaries on a schedule.">
        {paid ? (
          <ScheduledReportsConfig />
        ) : (
          <LockedFeature
            title="scheduled reports"
            description="Receive a periodic security summary by email for any monitored site."
            availableOn="Paid plans"
          />
        )}
        {planIncludes(plan, "agency") ? (
          <CloudCredentialsConfig />
        ) : (
          <LockedFeature
            title="cloud posture scanning"
            description="Connect AWS, Azure or GCP with read-only access to catch public storage buckets and misconfigurations."
            availableOn="Agency"
          />
        )}
      </Group>
    </div>
  );
}
