type UserLike = {
  app_metadata?: unknown;
};

type AssuranceLike = {
  currentLevel?: unknown;
};

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function authenticationMethods(claims: unknown): string[] {
  const value = record(claims)["amr"];
  if (!Array.isArray(value)) {
    return [];
  }

  return value.flatMap((entry) => {
    const method = record(entry)["method"];
    return typeof method === "string" ? [method] : [];
  });
}

export function isGoogleIdentity(user: UserLike): boolean {
  const metadata = record(user.app_metadata);
  // A linked Google identity does NOT prove the current account's primary
  // login provider was Google. Fail closed until hosted OAuth E2E qualifies it.
  return metadata["provider"] === "google";
}

export function isGoogleAal2(
  user: UserLike,
  claims: unknown,
  assurance: AssuranceLike,
): boolean {
  const claimRecord = record(claims);
  const methods = authenticationMethods(claims);

  return isGoogleIdentity(user)
    && claimRecord["aal"] === "aal2"
    && assurance.currentLevel === "aal2"
    && methods.includes("oauth")
    && methods.includes("totp");
}
