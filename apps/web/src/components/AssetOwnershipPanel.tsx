import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { CustomerAsset } from "@lumicsec/shared";
import { Badge } from "../components/ui/Badge.js";
import { Button } from "../components/ui/Button.js";
import {
  getAssetVerificationChallenges, postJson, type NewAssetChallenge,
} from "../lib/api.js";

export function AssetOwnershipPanel({
  asset, organizationId, csrfToken, canManage,
}: {
  asset: CustomerAsset;
  organizationId: string;
  csrfToken: string;
  canManage: boolean;
}) {
  const client = useQueryClient();
  const [method, setMethod] = useState<"dns_txt" | "https_file">("dns_txt");
  const [newChallenge, setNewChallenge] = useState<NewAssetChallenge | null>(null);
  const queryKey = ["ownership-challenges", organizationId, asset.id];
  const history = useQuery({
    queryKey,
    queryFn: () => getAssetVerificationChallenges(organizationId, asset.id),
    enabled: canManage,
    retry: false,
  });

  const issue = useMutation({
    mutationFn: () => postJson<{ challenge: NewAssetChallenge; scanningEnabled: false }>(
      "/v1/assets/verification/challenges", {
        organizationId, assetId: asset.id, method,
      }, csrfToken),
    onSuccess: async (response) => {
      setNewChallenge(response.challenge);
      await client.invalidateQueries({ queryKey });
      await client.invalidateQueries({ queryKey: ["org-audit", organizationId] });
    },
  });
  const check = useMutation({
    mutationFn: (challengeId: string) => postJson<{
      verified: true; assetId: string; scanningEnabled: false;
    }>("/v1/assets/verification/check", {
      organizationId, assetId: asset.id, challengeId,
    }, csrfToken),
    onSuccess: async () => {
      setNewChallenge(null);
      await client.invalidateQueries({ queryKey });
      await client.invalidateQueries({ queryKey: ["assets", organizationId] });
      await client.invalidateQueries({ queryKey: ["org-audit", organizationId] });
    },
  });
  const revoke = useMutation({
    mutationFn: () => postJson<{ revoked: true; scanningEnabled: false }>(
      "/v1/assets/verification/revoke", { organizationId, assetId: asset.id }, csrfToken),
    onSuccess: async () => {
      setNewChallenge(null);
      await client.invalidateQueries({ queryKey });
      await client.invalidateQueries({ queryKey: ["assets", organizationId] });
      await client.invalidateQueries({ queryKey: ["org-audit", organizationId] });
    },
  });

  const expiresAt = asset.verification_expires_at ? Date.parse(asset.verification_expires_at) : 0;
  const ownershipCurrent = asset.verification_status === "verified" && expiresAt > Date.now();
  const status = asset.verification_status === "revoked" ? "revoked"
    : ownershipCurrent ? "verified" : asset.verification_status === "verified" ? "expired" : "pending";
  const proofContent = newChallenge
    ? "lumicsec-verification=" + newChallenge.verification_token
    : "";

  return (
    <div className="mt-4 space-y-3 border-t border-white/10 pt-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="text-xs font-semibold uppercase tracking-wide text-slate-300">
          Ownership verification
        </div>
        <Badge variant={ownershipCurrent ? "success" : "warning"}>{status}</Badge>
      </div>
      <p className="text-xs leading-5 text-slate-400">
        Registration alone does not authorize a scan. Proof binds this exact asset
        and organization. A verified proof expires after 30 days and can be revoked.
      </p>
      {asset.verification_expires_at && (
        <p className="text-xs text-slate-500">
          {ownershipCurrent ? "Renew by" : "Last ownership expiration"}:{" "}
          {new Date(asset.verification_expires_at).toLocaleString()}
        </p>
      )}
      {!canManage ? (
        <p className="text-xs text-amber-200">Only an owner or admin can issue or revoke ownership proof.</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <select aria-label={"Ownership proof method for " + asset.display_name}
              className="h-10 rounded-lg border border-white/15 bg-slate-950 px-3 text-xs text-white"
              value={method} onChange={(event) => {
                setMethod(event.target.value as "dns_txt" | "https_file");
                setNewChallenge(null);
              }}>
              <option value="dns_txt">DNS TXT</option>
              <option value="https_file">HTTPS well-known file</option>
            </select>
            <Button type="button" size="sm" disabled={issue.isPending || !csrfToken}
              onClick={() => { setNewChallenge(null); issue.mutate(); }}>
              {ownershipCurrent ? "Create renewal challenge" : "Create ownership challenge"}
            </Button>
            <Button type="button" size="sm" variant="danger" disabled={revoke.isPending || !csrfToken}
              onClick={() => {
                if (window.confirm("Revoke ownership verification? Future scanning will remain disallowed.")) {
                  revoke.mutate();
                }
              }}>Revoke ownership</Button>
          </div>
          {issue.isError && <p role="alert" className="text-xs text-rose-300">{issue.error.message}</p>}
          {revoke.isError && <p role="alert" className="text-xs text-rose-300">{revoke.error.message}</p>}
          {revoke.isSuccess && <p className="text-xs text-emerald-200">Ownership status revoked in the database.</p>}
          {newChallenge && (
            <div className="space-y-2 rounded-xl border border-cyan-300/20 bg-slate-950/75 p-3">
              <p className="text-xs font-semibold text-cyan-200">New challenge — expires {new Date(newChallenge.expires_at).toLocaleString()}</p>
              <p className="text-xs text-slate-400">
                {method === "dns_txt"
                  ? "Publish exactly this TXT record at the specified DNS name."
                  : "Serve exactly this plain-text content over valid public HTTPS at the path below."}
              </p>
              <p className="break-all text-xs text-white">
                {method === "dns_txt" ? "DNS TXT host" : "HTTPS file URL"}:{" "}
                <code>{method === "dns_txt" ? newChallenge.verification_path
                  : "https://" + newChallenge.verification_host + newChallenge.verification_path}</code>
              </p>
              <p className="text-xs text-slate-300">Exact TXT value / file content:</p>
              <code className="block select-all break-all rounded-lg bg-slate-900 p-2 text-xs text-cyan-100">
                {proofContent}
              </code>
              <p className="text-xs leading-5 text-amber-200">
                The challenge token is shown only in this one response. Place it only at the exact domain
                you control; never use a public QR service or paste secrets into support messages.
              </p>
              <Button size="sm" type="button" variant="secondary" onClick={() => setNewChallenge(null)}>
                Hide challenge token
              </Button>
            </div>
          )}

          <p className="text-xs font-semibold text-slate-300">Challenge history</p>
          {history.isLoading && <p className="text-xs text-slate-500">Loading challenges…</p>}
          {history.isError && <p role="alert" className="text-xs text-rose-300">{history.error.message}</p>}
          {history.data?.challenges.length === 0 && <p className="text-xs text-slate-500">No challenges issued.</p>}
          {history.data?.challenges.map((challenge) => {
            const pending = !challenge.verified_at && !challenge.revoked_at
              && Date.parse(challenge.expires_at) > Date.now();
            return (
              <div key={challenge.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-white/10 p-2.5">
                <div className="text-xs text-slate-400">
                  {challenge.method === "dns_txt" ? "DNS TXT" : "HTTPS file"}
                  {" · "}{challenge.verified_at ? "verified"
                    : challenge.revoked_at ? "revoked" : pending ? "pending" : "expired"}
                  {" · "}{new Date(challenge.expires_at).toLocaleString()}
                </div>
                {pending && (
                  <Button size="sm" type="button" variant="secondary"
                    disabled={check.isPending || !csrfToken}
                    onClick={() => check.mutate(challenge.id)}>
                    Check published proof
                  </Button>
                )}
              </div>
            );
          })}
          {check.isError && (
            <p role="alert" className="text-xs text-amber-200">
              {check.error.message}. Ownership is NOT verified. If trusted backend configuration
              is missing, ask the local developer to configure a server-only Supabase secret key.
            </p>
          )}
          {check.isSuccess && <p className="text-xs text-emerald-200">Ownership proof verified. Automatic scanning is still disabled.</p>}
        </>
      )}
    </div>
  );
}
