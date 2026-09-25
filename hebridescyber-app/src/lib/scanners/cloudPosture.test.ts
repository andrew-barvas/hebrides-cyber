import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { generateKeyPairSync } from "crypto";
import {
  runCloudPostureChecks,
  checkAwsPublicBuckets,
  checkAzurePublicStorage,
  checkGcpPublicStorage,
  getGcpAccessToken,
  base64UrlEncode,
} from "./cloudPosture";

function mockSupabase(creds: Array<{ provider: string; credentials_encrypted: Record<string, string> }> | null) {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({ data: creds }),
      }),
    }),
  } as unknown as import("@supabase/supabase-js").SupabaseClient;
}

describe("runCloudPostureChecks", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 403 }));
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns not_configured when no credentials exist", async () => {
    const result = await runCloudPostureChecks(mockSupabase([]), "owner-1");
    expect(result.status).toBe("not_configured");
  });

  it("returns not_configured when query returns null", async () => {
    const result = await runCloudPostureChecks(mockSupabase(null), "owner-1");
    expect(result.status).toBe("not_configured");
  });

  it("returns checked for aws (fetch failures produce empty findings)", async () => {
    const supabase = mockSupabase([
      { provider: "aws", credentials_encrypted: { accessKeyId: "AKID", secretAccessKey: "secret" } },
    ]);
    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.provider).toBe("aws");
    }
  });

  it("returns findings for azure storage with public blob access", async () => {
    const mockFetch = vi.fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: "test-token" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          value: [
            { name: "publicaccount", properties: { allowBlobPublicAccess: true, supportsHttpsTrafficOnly: true, minimumTlsVersion: "TLS1_2" } },
            { name: "privateaccount", properties: { allowBlobPublicAccess: false, supportsHttpsTrafficOnly: true, minimumTlsVersion: "TLS1_2" } },
          ],
        }),
      });
    vi.stubGlobal("fetch", mockFetch);

    const supabase = mockSupabase([
      {
        provider: "azure",
        credentials_encrypted: {
          tenantId: "t1",
          clientId: "c1",
          clientSecret: "s1",
          subscriptionId: "sub1",
        },
      },
    ]);

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].title).toContain("publicaccount");
      expect(result.findings[0].severity).toBe("high");
      expect(result.findings[0].remediation).toBeDefined();
    }
  });

  it("handles azure token failure gracefully", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 401 })
    );

    const supabase = mockSupabase([
      {
        provider: "azure",
        credentials_encrypted: {
          tenantId: "t1",
          clientId: "c1",
          clientSecret: "bad",
          subscriptionId: "sub1",
        },
      },
    ]);

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.findings).toEqual([]);
    }
  });

  it("handles multiple providers", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 401 })
    );

    const supabase = mockSupabase([
      { provider: "aws", credentials_encrypted: { accessKeyId: "AKID", secretAccessKey: "secret" } },
      {
        provider: "azure",
        credentials_encrypted: { tenantId: "t1", clientId: "c1", clientSecret: "s1", subscriptionId: "sub1" },
      },
    ]);

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.provider).toBe("aws,azure");
    }
  });

  it("returns error on supabase query crash", async () => {
    const supabase = {
      from: () => { throw new Error("db down"); },
    } as unknown as import("@supabase/supabase-js").SupabaseClient;

    const result = await runCloudPostureChecks(supabase, "owner-1");
    expect(result.status).toBe("error");
    if (result.status === "error") {
      expect(result.note).toContain("db down");
    }
  });
});

describe("checkAwsPublicBuckets", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns empty array when ListBuckets fails", async () => {
    (globalThis.fetch as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ok: false, status: 403 });

    const findings = await checkAwsPublicBuckets({
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });

    expect(findings).toEqual([]);
  });

  it("flags bucket with no PublicAccessBlock (404 response)", async () => {
    const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(`
        <ListAllMyBucketsResult>
          <Buckets><Bucket><Name>test-bucket</Name></Bucket></Buckets>
        </ListAllMyBucketsResult>
      `),
    });
    mockFetch.mockResolvedValueOnce({ ok: false, status: 404 });

    const findings = await checkAwsPublicBuckets({
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].checkId).toBe("cloudPosture.awsPublicS3:test-bucket");
    expect(findings[0].remediation).toBeDefined();
  });

  it("flags bucket with incomplete PublicAccessBlock", async () => {
    const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(`
        <ListAllMyBucketsResult>
          <Buckets><Bucket><Name>partial-bucket</Name></Bucket></Buckets>
        </ListAllMyBucketsResult>
      `),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(`
        <PublicAccessBlockConfiguration>
          <BlockPublicAcls>true</BlockPublicAcls>
          <IgnorePublicAcls>true</IgnorePublicAcls>
          <BlockPublicPolicy>false</BlockPublicPolicy>
          <RestrictPublicBuckets>false</RestrictPublicBuckets>
        </PublicAccessBlockConfiguration>
      `),
    });

    const findings = await checkAwsPublicBuckets({
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].detail).toContain("BlockPublicPolicy");
    expect(findings[0].detail).toContain("RestrictPublicBuckets");
  });

  it("returns no findings when bucket is fully secured", async () => {
    const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(`
        <ListAllMyBucketsResult>
          <Buckets><Bucket><Name>secure-bucket</Name></Bucket></Buckets>
        </ListAllMyBucketsResult>
      `),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(`
        <PublicAccessBlockConfiguration>
          <BlockPublicAcls>true</BlockPublicAcls>
          <IgnorePublicAcls>true</IgnorePublicAcls>
          <BlockPublicPolicy>true</BlockPublicPolicy>
          <RestrictPublicBuckets>true</RestrictPublicBuckets>
        </PublicAccessBlockConfiguration>
      `),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      text: () => Promise.resolve(`
        <PolicyStatus><IsPublic>false</IsPublic></PolicyStatus>
      `),
    });

    const findings = await checkAwsPublicBuckets({
      accessKeyId: "AKIAIOSFODNN7EXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });

    expect(findings).toHaveLength(0);
  });
});

describe("checkAzurePublicStorage", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("flags storage account with HTTP traffic and weak TLS", async () => {
    const mockFetch = globalThis.fetch as ReturnType<typeof vi.fn>;
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({ access_token: "test-token" }),
    });
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        value: [
          { name: "badacct", properties: { allowBlobPublicAccess: false, supportsHttpsTrafficOnly: false, minimumTlsVersion: "TLS1_0" } },
        ],
      }),
    });

    const findings = await checkAzurePublicStorage({
      tenantId: "00000000-0000-0000-0000-000000000001",
      clientId: "00000000-0000-0000-0000-000000000002",
      clientSecret: "test-secret",
      subscriptionId: "00000000-0000-0000-0000-000000000003",
    });

    expect(findings).toHaveLength(2);
    expect(findings.some(f => f.checkId === "cloudPosture.azureHttpTraffic:badacct")).toBe(true);
    expect(findings.some(f => f.checkId === "cloudPosture.azureWeakTls:badacct")).toBe(true);
  });
});

describe("base64UrlEncode", () => {
  it("encodes a known input/output pair with URL-safe chars and no padding", () => {
    // "sure." base64-encodes to "c3VyZS4=" — the trailing "=" pad must be
    // stripped, and no "+"/"/" appear in this example, so also cover those
    // separately below.
    expect(base64UrlEncode("sure.")).toBe("c3VyZS4");
  });

  it("translates + and / to - and _", () => {
    // Byte sequence chosen to produce both "+" and "/" in standard base64.
    const input = Buffer.from([0xfb, 0xff, 0xbf]);
    const standard = input.toString("base64"); // "+/+/"-style output
    expect(standard).toMatch(/[+/]/);
    const urlSafe = base64UrlEncode(input);
    expect(urlSafe).not.toMatch(/[+/=]/);
    expect(urlSafe).toBe(standard.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""));
  });
});

describe("getGcpAccessToken", () => {
  // A real RSA keypair generated at test time so crypto.createSign() has a
  // valid key to sign with — never a hardcoded/committed key.
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  const serviceAccountKey = JSON.stringify({
    client_email: "test@test-project.iam.gserviceaccount.com",
    private_key: privateKey,
    token_uri: "https://oauth2.googleapis.com/token",
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns an access token on a successful exchange", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ access_token: "test-access-token" }),
      })
    );

    const token = await getGcpAccessToken(serviceAccountKey);
    expect(token).toBe("test-access-token");
  });

  it("returns null when the token endpoint rejects the request", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));

    const token = await getGcpAccessToken(serviceAccountKey);
    expect(token).toBeNull();
  });

  it("returns null for malformed key JSON", async () => {
    vi.stubGlobal("fetch", vi.fn());
    const token = await getGcpAccessToken("not json");
    expect(token).toBeNull();
  });

  it("returns null when required fields are missing", async () => {
    vi.stubGlobal("fetch", vi.fn());
    const token = await getGcpAccessToken(JSON.stringify({ client_email: "a@b.com" }));
    expect(token).toBeNull();
  });
});

describe("checkGcpPublicStorage", () => {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });

  const credentials = {
    projectId: "test-project",
    serviceAccountKey: JSON.stringify({
      client_email: "test@test-project.iam.gserviceaccount.com",
      private_key: privateKey,
      token_uri: "https://oauth2.googleapis.com/token",
    }),
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns [] without throwing when the token exchange fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));

    const findings = await checkGcpPublicStorage(credentials);
    expect(findings).toEqual([]);
  });

  it("flags a bucket missing Public Access Prevention", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ access_token: "tok" }) }) // token exchange
      .mockResolvedValueOnce({ ok: true, json: async () => ({ items: [{ name: "my-bucket" }] }) }) // list buckets
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          iamConfiguration: {
            publicAccessPrevention: "inherited",
            uniformBucketLevelAccess: { enabled: true },
          },
        }),
      }) // bucket metadata
      .mockResolvedValueOnce({ ok: true, json: async () => ({ bindings: [] }) }); // iam policy
    vi.stubGlobal("fetch", mockFetch);

    const findings = await checkGcpPublicStorage(credentials);
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe("cloudPosture.gcpPublicAccessPrevention:my-bucket");
    expect(findings[0].severity).toBe("high");
    expect(findings[0].remediation).toBeDefined();
  });

  it("flags a bucket using legacy ACLs instead of uniform access", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ access_token: "tok" }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ items: [{ name: "my-bucket" }] }) })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          iamConfiguration: {
            publicAccessPrevention: "enforced",
            uniformBucketLevelAccess: { enabled: false },
          },
        }),
      })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ bindings: [] }) });
    vi.stubGlobal("fetch", mockFetch);

    const findings = await checkGcpPublicStorage(credentials);
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe("cloudPosture.gcpUniformAccess:my-bucket");
    expect(findings[0].severity).toBe("medium");
  });

  it("flags a bucket with an allUsers IAM binding as a confirmed public bucket", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ access_token: "tok" }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ items: [{ name: "my-bucket" }] }) })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          iamConfiguration: {
            publicAccessPrevention: "enforced",
            uniformBucketLevelAccess: { enabled: true },
          },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          bindings: [{ role: "roles/storage.objectViewer", members: ["allUsers"] }],
        }),
      });
    vi.stubGlobal("fetch", mockFetch);

    const findings = await checkGcpPublicStorage(credentials);
    expect(findings).toHaveLength(1);
    expect(findings[0].checkId).toBe("cloudPosture.gcpPublicBucket:my-bucket");
    expect(findings[0].severity).toBe("critical");
  });

  it("returns no findings for a fully secured bucket", async () => {
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, json: async () => ({ access_token: "tok" }) })
      .mockResolvedValueOnce({ ok: true, json: async () => ({ items: [{ name: "secure-bucket" }] }) })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          iamConfiguration: {
            publicAccessPrevention: "enforced",
            uniformBucketLevelAccess: { enabled: true },
          },
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          bindings: [{ role: "roles/storage.objectViewer", members: ["user:someone@example.com"] }],
        }),
      });
    vi.stubGlobal("fetch", mockFetch);

    const findings = await checkGcpPublicStorage(credentials);
    expect(findings).toEqual([]);
  });
});

describe("runCloudPostureChecks with GCP", () => {
  function mockSupabaseGcp(serviceAccountKey: string) {
    return {
      from: () => ({
        select: () => ({
          eq: () => ({
            data: [{ provider: "gcp", credentials_encrypted: { projectId: "test-project", serviceAccountKey } }],
          }),
        }),
      }),
    } as unknown as import("@supabase/supabase-js").SupabaseClient;
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns checked with empty findings when GCP token exchange fails", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, status: 401 }));

    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const key = JSON.stringify({
      client_email: "test@test-project.iam.gserviceaccount.com",
      private_key: privateKey,
      token_uri: "https://oauth2.googleapis.com/token",
    });

    const result = await runCloudPostureChecks(mockSupabaseGcp(key), "owner-1");
    expect(result.status).toBe("checked");
    if (result.status === "checked") {
      expect(result.findings).toEqual([]);
      expect(result.provider).toBe("gcp");
    }
  });
});

describe("compliance mapping", () => {
  it("maps cloudPosture checkIds to compliance refs", async () => {
    const { getComplianceRefs } = await import("./compliance");

    expect(getComplianceRefs("cloudPosture.awsPublicS3:my-bucket").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.awsPublicS3Policy:my-bucket").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.awsAccountPublicAccess").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.azurePublicBlob:acct").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.azureHttpTraffic:acct").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.azureWeakTls:acct").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.gcpPublicBucket:bucket").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.gcpPublicAccessPrevention:bucket").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.gcpUniformAccess:bucket").length).toBeGreaterThan(0);
  });
});

describe("extendedToolCheckIds", () => {
  it("includes cloudPosture prefix", async () => {
    const { isExtendedToolFinding } = await import("../extendedToolCheckIds");
    expect(isExtendedToolFinding("cloudPosture.awsPublicS3:bucket")).toBe(true);
  });
});
