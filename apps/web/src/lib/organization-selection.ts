import { useState } from "react";
import type { CustomerOrganization } from "@lumicsec/shared";

// Browser-only UI preference. Never used as an authorization decision; every
// API call and database operation independently enforces tenant membership.
const storageKey = "lumicsec:active-organization";

export function useOrganizationSelection(organizations: CustomerOrganization[]) {
  const [preferredId, setPreferredId] = useState(() => {
    try { return sessionStorage.getItem(storageKey) ?? ""; } catch { return ""; }
  });
  const activeOrganizationId = organizations.some((organization) => organization.id === preferredId)
    ? preferredId
    : (organizations[0]?.id ?? "");
  const selectOrganization = (organizationId: string) => {
    if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(organizationId)) return;
    setPreferredId(organizationId);
    try { sessionStorage.setItem(storageKey, organizationId); } catch { /* UI preference only */ }
  };
  return { activeOrganizationId, selectOrganization };
}
