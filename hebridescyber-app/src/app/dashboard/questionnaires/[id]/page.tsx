"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import QuestionnaireReview from "@/components/questionnaire/QuestionnaireReview";
import PlanUpsell from "@/components/PlanUpsell";
import { useAppSession } from "@/components/app-shell/AppShell";
import { PageHeader } from "@/components/ui/page-header";
import { planIncludes } from "@/lib/planAccess";

export default function QuestionnaireReviewPage() {
  const { accessToken, plan } = useAppSession();
  const params = useParams<{ id: string }>();

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="$ ./questionnaires/review"
        title="Review draft answers"
        description="Accept, edit or reject each answer. Nothing is final until you accept it."
        actions={
          <Link href="/dashboard/questionnaires" className="text-sm text-neon hover:underline">
            All questionnaires
          </Link>
        }
      />
      {planIncludes(plan, "pro") ? <QuestionnaireReview token={accessToken} id={params.id} /> : <PlanUpsell plan={plan} />}
    </div>
  );
}
