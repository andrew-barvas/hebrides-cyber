"use client";

import QuestionnaireList from "@/components/questionnaire/QuestionnaireList";
import PlanUpsell from "@/components/PlanUpsell";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";
import { planIncludes } from "@/lib/planAccess";

export default function QuestionnairesPage() {
  const { accessToken, plan } = useAppSession();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./questionnaires"
        title="Security questionnaires"
        description="Upload a security questionnaire from an insurer or customer and get draft answers built from your own evidence, each citing where it comes from. You review, edit and accept every answer before you export it."
      />
      {planIncludes(plan, "pro") ? <QuestionnaireList token={accessToken} /> : <PlanUpsell plan={plan} />}
    </div>
  );
}
