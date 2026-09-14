// SCIM 2.0 user provisioning — handles inbound SCIM requests from identity
// providers (Okta, Azure AD, OneLogin) to automatically create, update, and
// deactivate org members when the IdP directory changes.
//
// Implements the minimum viable SCIM subset: Users resource with
// create/read/update/deactivate (not delete — SCIM best practice is to set
// active=false, not hard-delete). Groups are not implemented yet.

export type ScimUser = {
  schemas: string[];
  id?: string;
  userName: string;
  name?: { givenName?: string; familyName?: string };
  emails?: Array<{ value: string; primary?: boolean }>;
  active?: boolean;
  externalId?: string;
};

export type ScimListResponse = {
  schemas: string[];
  totalResults: number;
  startIndex: number;
  itemsPerPage: number;
  Resources: ScimUser[];
};

export type ScimError = {
  schemas: string[];
  status: string;
  detail: string;
};

const SCIM_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const SCIM_ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error";

export function scimError(status: number, detail: string): ScimError {
  return { schemas: [SCIM_ERROR_SCHEMA], status: String(status), detail };
}

export function parseScimUser(body: unknown): ScimUser | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  const userName = b.userName;
  if (typeof userName !== "string" || !userName) return null;

  const name = b.name as { givenName?: string; familyName?: string } | undefined;
  const emails = Array.isArray(b.emails)
    ? (b.emails as Array<{ value?: string; primary?: boolean }>)
        .filter((e) => typeof e.value === "string")
        .map((e) => ({ value: e.value as string, primary: e.primary === true }))
    : undefined;

  return {
    schemas: [SCIM_SCHEMA],
    userName,
    name: name ? { givenName: name.givenName, familyName: name.familyName } : undefined,
    emails,
    active: b.active !== false,
    externalId: typeof b.externalId === "string" ? b.externalId : undefined,
  };
}

export function toScimUser(member: {
  id: string;
  email: string;
  display_name?: string | null;
  active?: boolean;
  external_id?: string | null;
}): ScimUser {
  const nameParts = member.display_name?.split(" ") ?? [];
  return {
    schemas: [SCIM_SCHEMA],
    id: member.id,
    userName: member.email,
    name: nameParts.length > 0
      ? { givenName: nameParts[0], familyName: nameParts.slice(1).join(" ") || undefined }
      : undefined,
    emails: [{ value: member.email, primary: true }],
    active: member.active !== false,
    externalId: member.external_id ?? undefined,
  };
}

export function toScimListResponse(users: ScimUser[], startIndex: number = 1): ScimListResponse {
  return {
    schemas: [SCIM_LIST_SCHEMA],
    totalResults: users.length,
    startIndex,
    itemsPerPage: users.length,
    Resources: users,
  };
}

export function validateScimBearerToken(authHeader: string | undefined, expectedToken: string): boolean {
  if (!authHeader) return false;
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return false;
  return parts[1] === expectedToken;
}
