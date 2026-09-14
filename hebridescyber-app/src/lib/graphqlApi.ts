// GraphQL API layer — a thin schema and resolver set that exposes scan data
// via GraphQL for enterprise integrations. This is the schema definition and
// resolver logic; the actual /api/graphql route handler mounts it.

export type GqlContext = {
  userId: string;
  isAdmin: boolean;
};

export const SCHEMA = `
  type Query {
    scan(id: ID!): Scan
    scans(targetUrl: String, limit: Int): [Scan!]!
    target(id: ID!): MonitoredTarget
    targets: [MonitoredTarget!]!
  }

  type Scan {
    id: ID!
    targetUrl: String!
    status: String!
    score: Int
    createdAt: String!
    completedAt: String
    findingsCount: Int!
    findings: [Finding!]!
  }

  type Finding {
    checkId: String
    severity: String!
    title: String!
    detail: String!
    remediation: String
    cvssScore: Float
  }

  type MonitoredTarget {
    id: ID!
    url: String!
    lastScore: Int
    lastScanAt: String
  }
`;

export type ResolverFn<TArgs = Record<string, unknown>, TResult = unknown> = (
  args: TArgs,
  context: GqlContext,
) => Promise<TResult>;

export type GqlScan = {
  id: string;
  targetUrl: string;
  status: string;
  score: number | null;
  createdAt: string;
  completedAt: string | null;
  findingsCount: number;
  findings: GqlFinding[];
};

export type GqlFinding = {
  checkId: string | null;
  severity: string;
  title: string;
  detail: string;
  remediation: string | null;
  cvssScore: number | null;
};

export type GqlTarget = {
  id: string;
  url: string;
  lastScore: number | null;
  lastScanAt: string | null;
};

export function parseGraphqlQuery(body: unknown): { query: string; variables?: Record<string, unknown> } | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (typeof b.query !== "string") return null;
  return {
    query: b.query,
    variables: b.variables && typeof b.variables === "object" ? b.variables as Record<string, unknown> : undefined,
  };
}

export function extractOperationName(query: string): string | null {
  const match = query.match(/(?:query|mutation)\s+(\w+)/);
  return match?.[1] ?? null;
}

export function isIntrospectionQuery(query: string): boolean {
  return query.includes("__schema") || query.includes("__type");
}

export function validateQueryDepth(query: string, maxDepth: number = 7): boolean {
  let depth = 0;
  let maxFound = 0;
  for (const ch of query) {
    if (ch === "{") { depth++; maxFound = Math.max(maxFound, depth); }
    else if (ch === "}") depth--;
  }
  return maxFound <= maxDepth;
}
