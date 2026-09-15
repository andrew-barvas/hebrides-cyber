import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runCloudPostureChecks, checkAwsPublicBuckets, checkAzurePublicStorage } from "./cloudPosture";

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

describe("compliance mapping", () => {
  it("maps cloudPosture checkIds to compliance refs", async () => {
    const { getComplianceRefs } = await import("./compliance");

    expect(getComplianceRefs("cloudPosture.awsPublicS3:my-bucket").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.awsPublicS3Policy:my-bucket").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.awsAccountPublicAccess").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.azurePublicBlob:acct").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.azureHttpTraffic:acct").length).toBeGreaterThan(0);
    expect(getComplianceRefs("cloudPosture.azureWeakTls:acct").length).toBeGreaterThan(0);
  });
});

describe("extendedToolCheckIds", () => {
  it("includes cloudPosture prefix", async () => {
    const { isExtendedToolFinding } = await import("../extendedToolCheckIds");
    expect(isExtendedToolFinding("cloudPosture.awsPublicS3:bucket")).toBe(true);
  });
});
