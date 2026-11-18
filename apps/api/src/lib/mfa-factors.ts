// listFactors().totp contains VERIFIED factors only; pending enrollment lives in .all.
// Never treat a stale pending cookie as authority to pick a different factor.
export type TotpFactor = {
  id: string;
  factor_type: string;
  status: string;
  friendly_name?: string | null;
};

export type FactorLists = {
  all: readonly TotpFactor[];
  totp: readonly TotpFactor[];
};

const managedFactorPrefix = "LumicSec Authenticator ";

export function managedUnverifiedTotp(factors: FactorLists): TotpFactor[] {
  return factors.all.filter((factor) =>
    factor.factor_type === "totp"
    && factor.status === "unverified"
    && typeof factor.friendly_name === "string"
    && factor.friendly_name.startsWith(managedFactorPrefix)
  );
}

export function selectTotpChallengeFactor(factors: FactorLists, pendingId?: string): TotpFactor | null {
  if (pendingId) {
    return factors.all.find((factor) =>
      factor.id === pendingId && factor.factor_type === "totp" && factor.status === "unverified"
      && typeof factor.friendly_name === "string" && factor.friendly_name.startsWith(managedFactorPrefix)
    ) ?? null;
  }

  return factors.totp.find((factor) =>
    factor.factor_type === "totp" && factor.status === "verified"
  ) ?? null;
}
