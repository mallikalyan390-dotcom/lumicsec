import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Building2, Globe2, LockKeyhole, Plus, ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import type { CustomerAsset, CustomerOrganization } from "@lumicsec/shared";
import { Badge } from "../components/ui/Badge.js";
import { AssetOwnershipPanel } from "../components/AssetOwnershipPanel.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent, CardHeader } from "../components/ui/Card.js";
import { Input } from "../components/ui/Input.js";
import { getAssets, getAuthSession, getOrganizations, postJson } from "../lib/api.js";
import { useOrganizationSelection } from "../lib/organization-selection.js";

const fieldLabel = "mb-1.5 block text-xs font-medium text-slate-300";
const selectClass =
  "h-11 w-full rounded-xl border border-white/10 bg-slate-950/70 px-3 text-sm text-white outline-none focus:border-cyan-300/60";

export function AssetsPage() {
  const queryClient = useQueryClient();
  const session = useQuery({ queryKey: ["auth-session"], queryFn: getAuthSession });
  const organizationsQuery = useQuery({
    queryKey: ["organizations"],
    queryFn: getOrganizations,
  });


  const [organizationName, setOrganizationName] = useState("");
  const [assetKind, setAssetKind] = useState<"website" | "api">("website");
  const [assetName, setAssetName] = useState("");
  const [assetOrigin, setAssetOrigin] = useState("");

  const organizations = organizationsQuery.data?.organizations ?? [];
  const { activeOrganizationId, selectOrganization } = useOrganizationSelection(organizations);
  const activeOrganization = organizations.find((org) => org.id === activeOrganizationId);
  const activeRole = organizationsQuery.data?.memberships.find(
    (membership) => membership.organization_id === activeOrganizationId,
  )?.member_role;
  const canRegisterAssets = activeRole === "owner" || activeRole === "admin" || activeRole === "analyst";
  const canManageOwnership = activeRole === "owner" || activeRole === "admin";

  const assetsQuery = useQuery({
    queryKey: ["assets", activeOrganizationId],
    queryFn: () => getAssets(activeOrganizationId),
    enabled: Boolean(activeOrganizationId),
  });

  const createOrganization = useMutation({
    mutationFn: () => postJson<{ organization: CustomerOrganization }>(
      "/v1/organizations",
      { displayName: organizationName },
      session.data?.csrfToken ?? "",
    ),
    onSuccess: async (result) => {
      setOrganizationName("");
      selectOrganization(result.organization.id);
      await queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
  });

  const registerAsset = useMutation({
    mutationFn: () => postJson<{ asset: CustomerAsset; scanningEnabled: false }>(
      "/v1/assets",
      {
        organizationId: activeOrganizationId,
        kind: assetKind,
        displayName: assetName,
        origin: assetOrigin,
      },
      session.data?.csrfToken ?? "",
    ),
    onSuccess: async () => {
      setAssetName("");
      setAssetOrigin("");
      await queryClient.invalidateQueries({ queryKey: ["assets", activeOrganizationId] });
    },
  });

  const onCreateOrganization = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (organizationName.trim().length >= 2 && session.data?.csrfToken) {
      createOrganization.mutate();
    }
  };

  const onRegisterAsset = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!activeOrganizationId || !canRegisterAssets || !session.data?.csrfToken) return;
    registerAsset.mutate();
  };

  return (
    <div className="space-y-7">
      <section>
        <div className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-200">
          Customer workspace
        </div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">
          Organizations & assets
        </h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">
          Organize websites and APIs by tenant. Every asset remains pending until its
          ownership is independently verified. Registration does not start a scan.
        </p>
      </section>

      <Card>
        <CardHeader className="flex items-center gap-3">
          <Building2 size={19} className="text-cyan-200" />
          <div>
            <h2 className="font-semibold text-white">Your organizations</h2>
            <p className="mt-1 text-xs text-slate-500">
              Supabase tenant policies control which organizations you can access.
            </p>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {organizationsQuery.isLoading ? (
            <p className="text-sm text-slate-400">Loading organizations…</p>
          ) : organizationsQuery.isError ? (
            <p role="alert" className="text-sm text-rose-300">
              {organizationsQuery.error.message}
            </p>
          ) : organizations.length === 0 ? (
            <div className="rounded-xl border border-white/10 bg-slate-950/50 p-4 text-sm text-slate-400">
              No organization yet. Create one to begin registering assets.
            </div>
          ) : (
            <div>
              <label className={fieldLabel} htmlFor="organization-select">
                Active organization
              </label>
              <select
                id="organization-select"
                className={selectClass}
                value={activeOrganizationId}
                onChange={(event) => selectOrganization(event.target.value)}
              >
                {organizations.map((org) => (
                  <option key={org.id} value={org.id}>{org.display_name}</option>
                ))}
              </select>
              <p className="mt-2 text-xs text-slate-500">
                Your role: {activeRole ?? "unknown"}. Only permitted assets are returned by RLS.
              </p>
            </div>
          )}

          <form className="flex flex-col gap-3 sm:flex-row sm:items-end" onSubmit={onCreateOrganization}>
            <div className="grow">
              <label className={fieldLabel} htmlFor="organization-name">
                Create an organization
              </label>
              <Input
                id="organization-name"
                value={organizationName}
                onChange={(event) => setOrganizationName(event.target.value)}
                minLength={2}
                maxLength={160}
                placeholder="Example: Acme Engineering"
                required
              />
            </div>
            <Button
              type="submit"
              disabled={createOrganization.isPending || !session.data?.csrfToken}
            >
              <Plus size={15} />
              {createOrganization.isPending ? "Creating…" : "Create organization"}
            </Button>
          </form>
          {createOrganization.isError && (
            <p role="alert" className="text-xs text-rose-300">{createOrganization.error.message}</p>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-5 xl:grid-cols-[1fr_1.1fr]">
        <Card>
          <CardHeader className="flex items-center gap-3">
            <Globe2 size={19} className="text-cyan-200" />
            <div>
              <h2 className="font-semibold text-white">Register a pending asset</h2>
              <p className="mt-1 text-xs text-slate-500">
                Exact public HTTPS origin only; no paths, query strings or private IPs.
              </p>
            </div>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={onRegisterAsset}>
              <div>
                <label className={fieldLabel} htmlFor="asset-kind">Asset type</label>
                <select
                  className={selectClass}
                  id="asset-kind"
                  value={assetKind}
                  onChange={(event) => setAssetKind(event.target.value as "website" | "api")}
                >
                  <option value="website">Website</option>
                  <option value="api">API</option>
                </select>
              </div>
              <div>
                <label className={fieldLabel} htmlFor="asset-name">Asset display name</label>
                <Input
                  id="asset-name"
                  placeholder="Example: Customer portal"
                  minLength={2}
                  maxLength={160}
                  required
                  value={assetName}
                  onChange={(event) => setAssetName(event.target.value)}
                />
              </div>
              <div>
                <label className={fieldLabel} htmlFor="asset-origin">Public HTTPS origin</label>
                <Input
                  id="asset-origin"
                  type="url"
                  placeholder="https://yourdomain.com"
                  required
                  value={assetOrigin}
                  onChange={(event) => setAssetOrigin(event.target.value)}
                />
              </div>
              <Button
                className="w-full"
                type="submit"
                disabled={!activeOrganizationId || !canRegisterAssets || registerAsset.isPending || !session.data?.csrfToken}
              >
                <Plus size={16} />
                {registerAsset.isPending ? "Registering…" : "Register pending asset"}
              </Button>
              {registerAsset.isError && (
                <p role="alert" className="text-xs text-rose-300">{registerAsset.error.message}</p>
              )}
              {registerAsset.isSuccess && (
                <p className="text-xs text-emerald-200">Asset saved. Ownership verification remains pending.</p>
              )}
              {!canRegisterAssets && activeOrganizationId && (
                <p className="text-xs text-amber-200">Your organization role cannot register assets.</p>
              )}
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex items-center gap-3">
            <ShieldAlert size={19} className="text-cyan-200" />
            <div>
              <h2 className="font-semibold text-white">Registered assets</h2>
              <p className="mt-1 text-xs text-slate-500">
                For {activeOrganization?.display_name ?? "your selected organization"}.
              </p>
            </div>
          </CardHeader>
          <CardContent>
            {!activeOrganizationId ? (
              <p className="text-sm text-slate-400">Create an organization first.</p>
            ) : assetsQuery.isLoading ? (
              <p className="text-sm text-slate-400">Loading assets…</p>
            ) : assetsQuery.isError ? (
              <p role="alert" className="text-sm text-rose-300">{assetsQuery.error.message}</p>
            ) : (assetsQuery.data?.assets.length ?? 0) === 0 ? (
              <p className="text-sm leading-6 text-slate-400">
                No assets registered for this organization.
              </p>
            ) : (
              <div className="space-y-3">
                {assetsQuery.data?.assets.map((asset) => (
                  <div key={asset.id} className="rounded-xl border border-white/10 bg-slate-950/50 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-sm font-semibold text-white">{asset.display_name}</div>
                      <Badge variant={asset.verification_status === "verified" ? "success" : "warning"}>
                        {asset.verification_status}
                      </Badge>
                    </div>
                    <p className="mt-2 break-all font-mono text-xs text-cyan-200">
                      {asset.canonical_origin}
                    </p>
                    <p className="mt-2 text-xs text-slate-500">
                      {asset.asset_kind.toUpperCase()} · No automatic scan permission
                    </p>
                    <AssetOwnershipPanel
                      asset={asset} organizationId={activeOrganizationId}
                      csrfToken={session.data?.csrfToken ?? ""} canManage={canManageOwnership}
                    />
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="flex gap-3 rounded-xl border border-amber-400/20 bg-amber-400/5 p-4 text-xs leading-6 text-amber-100">
        <LockKeyhole size={18} className="mt-0.5 shrink-0" />
        <p>
          Register only assets you own or have permission to verify. Ownership challenges
          require independently observed DNS TXT or bounded HTTPS proof. Scanning, reporting,
          and assessment authorization remain disabled until separately qualified.
        </p>
      </div>
    </div>
  );
}
