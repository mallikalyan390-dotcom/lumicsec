import type {
  ApiHealthResponse,
  AuthSessionResponse,
  CustomerAssetsResponse,
  CustomerOrganizationsResponse,
} from "@lumicsec/shared";

const apiBase = import.meta.env.VITE_API_BASE_URL ?? "";

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (!headers.has("accept")) {
    headers.set("accept", "application/json");
  }

  const response = await fetch(apiBase + path, {
    ...init,
    headers,
    credentials: "include",
    cache: "no-store",
  });

  const payload: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const record = payload !== null && typeof payload === "object" ? payload as Record<string, unknown> : {};
    const message = typeof record["message"] === "string"
      ? record["message"]
      : typeof record["error"] === "string"
        ? record["error"]
        : "The request could not be completed.";
    throw new Error(message);
  }

  return payload as T;
}

/** Authenticated, no-store GET for tenant-filtered assessment history. */
export function getJson<T>(path: string) {
  return requestJson<T>(path);
}

export function getAuthSession() {
  return requestJson<AuthSessionResponse>("/auth/session");
}

export function getApiHealth() {
  return requestJson<ApiHealthResponse>("/healthz");
}

export function postJson<T>(path: string, body: unknown, csrfToken: string) {
  return requestJson<T>(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify(body),
  });
}

export function getOrganizations() {
  return requestJson<CustomerOrganizationsResponse>("/v1/organizations");
}

export function getAssets(organizationId: string) {
  return requestJson<CustomerAssetsResponse>(
    "/v1/assets?organizationId=" + encodeURIComponent(organizationId),
  );
}

/** Verified factors only; this response intentionally never includes TOTP keys. */
export type VerifiedTotpFactor = { id: string; friendlyName: string };
export type VerifiedTotpFactorsResponse = { verifiedTotpFactors: VerifiedTotpFactor[] };

export function getVerifiedTotpFactors() {
  return requestJson<VerifiedTotpFactorsResponse>("/auth/mfa/factors");
}

export type OrganizationRole = "owner" | "admin" | "member" | "analyst" | "viewer";
export type OrganizationMember = {
  user_id: string;
  member_role: OrganizationRole;
  member_status: "active" | "suspended";
  member_email: string;
  joined_at: string;
};
export type OrganizationInvite = {
  id: string;
  invite_email: string;
  invite_role: "admin" | "member";
  expires_at: string;
  created_at: string;
  invite_status: "pending" | "expired" | "revoked" | "accepted";
};
export type OrganizationAuditEvent = {
  id: number;
  actor_id: string | null;
  action: string;
  event_summary: string;
  created_at: string;
};

export function getOrganizationMembers(organizationId: string) {
  return requestJson<{ members: OrganizationMember[] }>(
    "/v1/organizations/" + encodeURIComponent(organizationId) + "/members");
}
export function getOrganizationInvitations(organizationId: string) {
  return requestJson<{ invitations: OrganizationInvite[] }>(
    "/v1/organizations/" + encodeURIComponent(organizationId) + "/invitations");
}
export function getOrganizationAudit(organizationId: string) {
  return requestJson<{ events: OrganizationAuditEvent[] }>(
    "/v1/organizations/" + encodeURIComponent(organizationId) + "/audit");
}

export type AssetVerificationChallenge = {
  id: string;
  organization_id: string;
  asset_id: string;
  method: "dns_txt" | "https_file";
  created_at: string;
  expires_at: string;
  verified_at: string | null;
  revoked_at: string | null;
};
export type NewAssetChallenge = {
  challenge_id: string;
  verification_token: string;
  verification_host: string;
  verification_path: string;
  expires_at: string;
};
export function getAssetVerificationChallenges(organizationId: string, assetId: string) {
  return requestJson<{ challenges: AssetVerificationChallenge[] }>(
    "/v1/assets/verification/challenges?organizationId="
    + encodeURIComponent(organizationId) + "&assetId=" + encodeURIComponent(assetId));
}
