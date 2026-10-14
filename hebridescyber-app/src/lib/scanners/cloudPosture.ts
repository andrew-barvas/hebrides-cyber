// E-32: Cloud posture scanning — checks public misconfigurations in
// AWS/Azure/GCP accounts using read-only API calls. Requires stored
// credentials in cloud_credentials table.
//
// AWS S3 bucket policy checks, Azure storage account public access checks,
// and GCS bucket public access checks. Extended checks (IAM policy review
// beyond public-member bindings, network security groups, encryption-at-rest)
// are future work.
//
// AWS calls use SigV4-signed fetch (no SDK dependency) — the three S3
// APIs we need (ListBuckets, GetPublicAccessBlock, GetBucketPolicyStatus)
// are simple XML responses that don't need the full SDK. GCP has no
// equivalent simple request-signing scheme, so its service account
// authenticates via a self-signed JWT exchanged for an OAuth2 access token
// (RFC 7523), then calls the JSON Cloud Storage API directly — still no SDK
// dependency, just fetch + Node's crypto.
import { createHmac, createHash, createSign } from "crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { decryptCredentials } from "../credentialEncryption";
import type { Finding } from "./index";
import {
  AWS_PUBLIC_S3_BUCKET,
  AWS_PUBLIC_S3_POLICY,
  AWS_ACCOUNT_PUBLIC_ACCESS,
  AZURE_PUBLIC_BLOB,
  AZURE_HTTP_TRAFFIC,
  AZURE_WEAK_TLS,
  GCP_PUBLIC_ACCESS_PREVENTION,
  GCP_UNIFORM_ACCESS,
  GCP_PUBLIC_BUCKET,
} from "./remediationText";

const REQUEST_TIMEOUT_MS = 15_000;
const MAX_BUCKETS_TO_CHECK = 100;

export type CloudCheckResult =
  | { status: "checked"; findings: Finding[]; provider: string }
  | { status: "not_applicable"; note: string }
  | { status: "not_configured"; note: string }
  | { status: "error"; note: string; findings: Finding[] };

// ---- AWS SigV4 signing helpers ---------------------------------------------

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

function getSignatureKey(secretKey: string, dateStamp: string, region: string, service: string): Buffer {
  const kDate = hmacSha256(`AWS4${secretKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  return hmacSha256(kService, "aws4_request");
}

async function awsSignedFetch(
  url: string,
  credentials: { accessKeyId: string; secretAccessKey: string },
  region: string,
  service: string
): Promise<Response> {
  const parsedUrl = new URL(url);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const dateStamp = amzDate.slice(0, 8);

  const canonicalQuerystring = parsedUrl.searchParams.toString();
  const payloadHash = sha256Hex("");
  const canonicalHeaders = `host:${parsedUrl.host}\nx-amz-content-sha256:${payloadHash}\nx-amz-date:${amzDate}\n`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date";

  const canonicalRequest = [
    "GET",
    parsedUrl.pathname,
    canonicalQuerystring,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const signingKey = getSignatureKey(credentials.secretAccessKey, dateStamp, region, service);
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");

  const authHeader = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return fetch(url, {
    headers: {
      Authorization: authHeader,
      "x-amz-date": amzDate,
      "x-amz-content-sha256": payloadHash,
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
}

// ---- AWS S3 public bucket check --------------------------------------------

function extractXmlValues(xml: string, tag: string): string[] {
  const re = new RegExp(`<${tag}>([^<]*)</${tag}>`, "g");
  const values: string[] = [];
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) values.push(m[1]);
  return values;
}

function extractXmlBool(xml: string, tag: string): boolean | null {
  const match = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
  if (!match) return null;
  return match[1].toLowerCase() === "true";
}

export async function checkAwsPublicBuckets(credentials: {
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}): Promise<Finding[]> {
  const findings: Finding[] = [];
  const region = credentials.region || "us-east-1";

  try {
    // 1. ListBuckets — always goes to s3.amazonaws.com (global endpoint)
    const listRes = await awsSignedFetch(
      "https://s3.amazonaws.com/",
      credentials,
      "us-east-1",
      "s3"
    );
    if (!listRes.ok) return findings;
    const listXml = await listRes.text();

    const bucketNames = extractXmlValues(listXml, "Name");
    const bucketsToCheck = bucketNames.slice(0, MAX_BUCKETS_TO_CHECK);

    // 2. For each bucket, check PublicAccessBlock and BucketPolicyStatus
    for (const bucket of bucketsToCheck) {
      try {
        // GetPublicAccessBlock
        const pabRes = await awsSignedFetch(
          `https://${bucket}.s3.${region}.amazonaws.com/?publicAccessBlock`,
          credentials,
          region,
          "s3"
        );

        if (pabRes.status === 404) {
          // No PublicAccessBlock configured at all — this is a finding
          findings.push({
            severity: "high",
            title: `AWS S3 bucket missing PublicAccessBlock: ${bucket}`,
            detail: `S3 bucket "${bucket}" has no PublicAccessBlock configuration. Without it, bucket policies and ACLs can grant public access.`,
            checkId: `cloudPosture.awsPublicS3:${bucket}`,
            remediation: AWS_PUBLIC_S3_BUCKET,
          });
          continue;
        }

        if (pabRes.ok) {
          const pabXml = await pabRes.text();
          const blockPublicAcls = extractXmlBool(pabXml, "BlockPublicAcls");
          const blockPublicPolicy = extractXmlBool(pabXml, "BlockPublicPolicy");
          const ignorePublicAcls = extractXmlBool(pabXml, "IgnorePublicAcls");
          const restrictPublicBuckets = extractXmlBool(pabXml, "RestrictPublicBuckets");

          if (!blockPublicAcls || !blockPublicPolicy || !ignorePublicAcls || !restrictPublicBuckets) {
            const missing: string[] = [];
            if (!blockPublicAcls) missing.push("BlockPublicAcls");
            if (!blockPublicPolicy) missing.push("BlockPublicPolicy");
            if (!ignorePublicAcls) missing.push("IgnorePublicAcls");
            if (!restrictPublicBuckets) missing.push("RestrictPublicBuckets");
            findings.push({
              severity: "high",
              title: `AWS S3 bucket has incomplete PublicAccessBlock: ${bucket}`,
              detail: `S3 bucket "${bucket}" does not have all four PublicAccessBlock settings enabled. Missing: ${missing.join(", ")}.`,
              checkId: `cloudPosture.awsPublicS3:${bucket}`,
              remediation: AWS_PUBLIC_S3_BUCKET,
            });
            continue;
          }
        }

        // GetBucketPolicyStatus — check if bucket policy grants public access
        const policyRes = await awsSignedFetch(
          `https://${bucket}.s3.${region}.amazonaws.com/?policyStatus`,
          credentials,
          region,
          "s3"
        );

        if (policyRes.ok) {
          const policyXml = await policyRes.text();
          const isPublic = extractXmlBool(policyXml, "IsPublic");
          if (isPublic === true) {
            findings.push({
              severity: "critical",
              title: `AWS S3 bucket policy allows public access: ${bucket}`,
              detail: `S3 bucket "${bucket}" has a bucket policy that grants public access. This may expose sensitive data to the internet.`,
              checkId: `cloudPosture.awsPublicS3Policy:${bucket}`,
              remediation: AWS_PUBLIC_S3_POLICY,
            });
          }
        }
      } catch {
        // Per-bucket errors (permissions, region mismatch) — skip silently
      }
    }
  } catch {
    // ListBuckets failed — credential or network issue
  }
  return findings;
}

// ---- AWS IAM check: account-level S3 public access block -------------------

export async function checkAwsAccountPublicAccess(credentials: {
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}): Promise<Finding[]> {
  const findings: Finding[] = [];
  const region = credentials.region || "us-east-1";

  try {
    const res = await awsSignedFetch(
      `https://s3-control.${region}.amazonaws.com/v20180820/configuration/publicAccessBlock`,
      { ...credentials },
      region,
      "s3"
    );

    if (res.status === 404) {
      findings.push({
        severity: "high",
        title: "AWS account-level S3 PublicAccessBlock not configured",
        detail: "The AWS account does not have account-level S3 Block Public Access enabled. Individual buckets can be made public unless each one has its own block.",
        checkId: "cloudPosture.awsAccountPublicAccess",
        remediation: AWS_ACCOUNT_PUBLIC_ACCESS,
      });
    } else if (res.ok) {
      const xml = await res.text();
      const blockAll = extractXmlBool(xml, "BlockPublicAcls") &&
        extractXmlBool(xml, "BlockPublicPolicy") &&
        extractXmlBool(xml, "IgnorePublicAcls") &&
        extractXmlBool(xml, "RestrictPublicBuckets");

      if (!blockAll) {
        findings.push({
          severity: "medium",
          title: "AWS account-level S3 PublicAccessBlock is incomplete",
          detail: "The AWS account has S3 Block Public Access configured but not all four settings are enabled.",
          checkId: "cloudPosture.awsAccountPublicAccess",
          remediation: AWS_ACCOUNT_PUBLIC_ACCESS,
        });
      }
    }
  } catch {
    // s3-control API may not be available — skip
  }
  return findings;
}

// ---- Azure storage public access check -------------------------------------

export async function checkAzurePublicStorage(credentials: {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId: string;
}): Promise<Finding[]> {
  const findings: Finding[] = [];
  try {
    const tokenRes = await fetch(
      `https://login.microsoftonline.com/${credentials.tenantId}/oauth2/v2.0/token`,
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "client_credentials",
          client_id: credentials.clientId,
          client_secret: credentials.clientSecret,
          scope: "https://management.azure.com/.default",
        }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      }
    );
    if (!tokenRes.ok) return findings;
    const { access_token } = (await tokenRes.json()) as { access_token: string };

    const storageRes = await fetch(
      `https://management.azure.com/subscriptions/${credentials.subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01`,
      {
        headers: { Authorization: `Bearer ${access_token}` },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      }
    );
    if (!storageRes.ok) return findings;
    const { value: accounts } = (await storageRes.json()) as {
      value: Array<{
        name: string;
        properties?: {
          allowBlobPublicAccess?: boolean;
          minimumTlsVersion?: string;
          supportsHttpsTrafficOnly?: boolean;
        };
      }>;
    };

    for (const acct of accounts ?? []) {
      if (acct.properties?.allowBlobPublicAccess === true) {
        findings.push({
          severity: "high",
          title: `Azure Storage account allows public blob access: ${acct.name}`,
          detail: `Storage account "${acct.name}" has allowBlobPublicAccess enabled, meaning individual containers can be set to public.`,
          checkId: `cloudPosture.azurePublicBlob:${acct.name}`,
          remediation: AZURE_PUBLIC_BLOB,
        });
      }

      if (acct.properties?.supportsHttpsTrafficOnly === false) {
        findings.push({
          severity: "medium",
          title: `Azure Storage account allows HTTP traffic: ${acct.name}`,
          detail: `Storage account "${acct.name}" does not enforce HTTPS-only traffic. Data in transit may be intercepted.`,
          checkId: `cloudPosture.azureHttpTraffic:${acct.name}`,
          remediation: AZURE_HTTP_TRAFFIC,
        });
      }

      const tls = acct.properties?.minimumTlsVersion;
      if (tls && tls !== "TLS1_2") {
        findings.push({
          severity: "medium",
          title: `Azure Storage account allows weak TLS: ${acct.name}`,
          detail: `Storage account "${acct.name}" allows TLS version ${tls}. Minimum should be TLS 1.2.`,
          checkId: `cloudPosture.azureWeakTls:${acct.name}`,
          remediation: AZURE_WEAK_TLS,
        });
      }
    }
  } catch {
    // credential or network issue — silent, not a finding
  }
  return findings;
}

// ---- GCP OAuth2 JWT-bearer token exchange -----------------------------------
//
// GCP has no simple "sign a GET request" scheme like AWS SigV4 — a service
// account authenticates by self-signing a JWT and exchanging it for a
// short-lived OAuth2 access token (RFC 7523), which is then sent as a normal
// Bearer token on subsequent calls.

/** Base64url encode (no padding), per RFC 4648 §5 — used for the JWT header/claims/signature. */
export function base64UrlEncode(input: Buffer | string): string {
  const base64 = Buffer.isBuffer(input) ? input.toString("base64") : Buffer.from(input).toString("base64");
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function getGcpAccessToken(serviceAccountKeyJson: string): Promise<string | null> {
  try {
    const key = JSON.parse(serviceAccountKeyJson) as {
      client_email?: string;
      private_key?: string;
      token_uri?: string;
    };
    const clientEmail = key.client_email;
    const privateKey = key.private_key;
    const tokenUri = key.token_uri || "https://oauth2.googleapis.com/token";
    if (!clientEmail || !privateKey) return null;

    const nowSeconds = Math.floor(Date.now() / 1000);
    const header = { alg: "RS256", typ: "JWT" };
    const claims = {
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/devstorage.read_only",
      aud: tokenUri,
      exp: nowSeconds + 3600,
      iat: nowSeconds,
    };

    const headerB64 = base64UrlEncode(JSON.stringify(header));
    const claimsB64 = base64UrlEncode(JSON.stringify(claims));
    const signingInput = `${headerB64}.${claimsB64}`;

    const signatureB64 = createSign("RSA-SHA256").update(signingInput).sign(privateKey, "base64");
    const signatureB64Url = base64UrlEncode(Buffer.from(signatureB64, "base64"));

    const jwt = `${signingInput}.${signatureB64Url}`;

    const tokenRes = await fetch(tokenUri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwt,
      }),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!tokenRes.ok) return null;
    const { access_token } = (await tokenRes.json()) as { access_token: string };
    return access_token ?? null;
  } catch {
    return null;
  }
}

// ---- GCS public bucket check -------------------------------------------------

export async function checkGcpPublicStorage(credentials: {
  projectId: string;
  serviceAccountKey: string;
}): Promise<Finding[]> {
  const findings: Finding[] = [];

  const accessToken = await getGcpAccessToken(credentials.serviceAccountKey);
  if (!accessToken) return findings;

  try {
    const listRes = await fetch(
      `https://storage.googleapis.com/storage/v1/b?project=${encodeURIComponent(credentials.projectId)}&fields=items(name)`,
      {
        headers: { Authorization: `Bearer ${accessToken}` },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      }
    );
    if (!listRes.ok) return findings;
    const { items } = (await listRes.json()) as { items?: Array<{ name: string }> };
    const buckets = (items ?? []).map((b) => b.name).slice(0, MAX_BUCKETS_TO_CHECK);

    for (const bucket of buckets) {
      try {
        const metaRes = await fetch(
          `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}?fields=iamConfiguration`,
          {
            headers: { Authorization: `Bearer ${accessToken}` },
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          }
        );

        if (metaRes.ok) {
          const meta = (await metaRes.json()) as {
            iamConfiguration?: {
              publicAccessPrevention?: string;
              uniformBucketLevelAccess?: { enabled?: boolean };
            };
          };

          const pap = meta.iamConfiguration?.publicAccessPrevention;
          if (pap !== "enforced") {
            findings.push({
              severity: "high",
              title: `GCS bucket missing Public Access Prevention: ${bucket}`,
              detail: `GCS bucket "${bucket}" does not have Public Access Prevention enforced (current: ${pap ?? "inherited"}). Without it, IAM bindings or ACLs can grant public access.`,
              checkId: `cloudPosture.gcpPublicAccessPrevention:${bucket}`,
              remediation: GCP_PUBLIC_ACCESS_PREVENTION,
            });
          }

          if (meta.iamConfiguration?.uniformBucketLevelAccess?.enabled === false) {
            findings.push({
              severity: "medium",
              title: `GCS bucket uses legacy ACLs instead of uniform access: ${bucket}`,
              detail: `GCS bucket "${bucket}" has Uniform bucket-level access disabled, meaning legacy per-object ACLs can grant access that's harder to audit for public exposure.`,
              checkId: `cloudPosture.gcpUniformAccess:${bucket}`,
              remediation: GCP_UNIFORM_ACCESS,
            });
          }
        }

        const iamRes = await fetch(
          `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/iam`,
          {
            headers: { Authorization: `Bearer ${accessToken}` },
            signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
          }
        );

        if (iamRes.ok) {
          const iamPolicy = (await iamRes.json()) as {
            bindings?: Array<{ role: string; members?: string[] }>;
          };
          const isPublic = (iamPolicy.bindings ?? []).some((b) =>
            (b.members ?? []).some((m) => m === "allUsers" || m === "allAuthenticatedUsers")
          );
          if (isPublic) {
            findings.push({
              severity: "critical",
              title: `GCS bucket is publicly accessible: ${bucket}`,
              detail: `GCS bucket "${bucket}" has an IAM binding granting access to "allUsers" or "allAuthenticatedUsers". This exposes its contents to the internet.`,
              checkId: `cloudPosture.gcpPublicBucket:${bucket}`,
              remediation: GCP_PUBLIC_BUCKET,
            });
          }
        }
      } catch {
        // Per-bucket errors (permissions, deleted bucket) — skip silently
      }
    }
  } catch {
    // ListBuckets failed — credential or network issue
  }

  return findings;
}

// ---- Orchestrator ----------------------------------------------------------

export async function runCloudPostureChecks(
  supabaseAdmin: SupabaseClient,
  ownerId: string
): Promise<CloudCheckResult> {
  try {
    const { data: creds } = await supabaseAdmin
      .from("cloud_credentials")
      .select("provider, credentials_encrypted")
      .eq("owner", ownerId);

    if (!creds || creds.length === 0) {
      return { status: "not_configured", note: "No cloud credentials stored" };
    }

    const allFindings: Finding[] = [];

    for (const cred of creds) {
      let credentials: Record<string, string>;
      try {
        credentials = decryptCredentials(cred.credentials_encrypted);
      } catch {
        // Can't decrypt (CREDENTIALS_ENC_KEY missing or rotated) — skip this
        // credential rather than failing the whole scan or exposing anything.
        continue;
      }
      if (cred.provider === "aws" && credentials.accessKeyId) {
        const awsCreds = credentials as Parameters<typeof checkAwsPublicBuckets>[0];
        const [bucketFindings, accountFindings] = await Promise.all([
          checkAwsPublicBuckets(awsCreds),
          checkAwsAccountPublicAccess(awsCreds),
        ]);
        allFindings.push(...bucketFindings, ...accountFindings);
      } else if (cred.provider === "azure" && credentials.tenantId) {
        const f = await checkAzurePublicStorage(credentials as Parameters<typeof checkAzurePublicStorage>[0]);
        allFindings.push(...f);
      } else if (cred.provider === "gcp" && credentials.serviceAccountKey) {
        const f = await checkGcpPublicStorage(credentials as Parameters<typeof checkGcpPublicStorage>[0]);
        allFindings.push(...f);
      }
    }

    return { status: "checked", findings: allFindings, provider: creds.map((c) => c.provider).join(",") };
  } catch (err) {
    return { status: "error", note: (err as Error).message, findings: [] };
  }
}
