// The CI files customers download from /ci/ (public/ci/): one scan-gate
// script and a template per CI system that runs it. Listed once here for
// the /docs/ci page and its tests. Server-only: the page reads the files at
// build time, so what it shows is exactly what /ci/<file> serves.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

export const CI_SCRIPT = "hebrides-scan.sh";

export type CiTemplate = {
  id: string;
  name: string;
  /** File name under public/ci/, served at /ci/<file>. */
  file: string;
  /** Where it goes in the customer's repository. */
  saveAs: string;
  /** Where the API key is stored as a secret in that CI system. */
  secret: string;
};

export const CI_TEMPLATES: CiTemplate[] = [
  { id: "github-actions", name: "GitHub Actions", file: "github-actions.yml", saveAs: ".github/workflows/security-scan.yml", secret: "Settings → Secrets and variables → Actions" },
  { id: "gitlab", name: "GitLab CI", file: "gitlab-ci.yml", saveAs: ".gitlab-ci.yml (add the job, or include the file)", secret: "Settings → CI/CD → Variables (masked)" },
  { id: "azure-devops", name: "Azure DevOps", file: "azure-pipelines.yml", saveAs: "azure-pipelines.yml", secret: "Pipeline → Variables (keep this value secret)" },
  { id: "bitbucket", name: "Bitbucket Pipelines", file: "bitbucket-pipelines.yml", saveAs: "bitbucket-pipelines.yml", secret: "Repository settings → Repository variables (secured)" },
  { id: "jenkins", name: "Jenkins", file: "jenkinsfile.groovy", saveAs: "Jenkinsfile", secret: "Credentials → Secret text, id hebrides-cyber-api-key" },
];

const CI_DIR = path.join(process.cwd(), "public", "ci");

export function readCiFile(file: string): string {
  return readFileSync(path.join(CI_DIR, path.basename(file)), "utf8");
}

/** SHA-256 of the file's bytes as served, for customers to check their copy. */
export function ciFileSha256(file: string): string {
  return createHash("sha256").update(readFileSync(path.join(CI_DIR, path.basename(file)))).digest("hex");
}
