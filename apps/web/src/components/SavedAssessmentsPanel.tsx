import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import type { CustomerAsset } from "@lumicsec/shared";
import { AlertTriangle, Database, FileCheck2, LockKeyhole } from "lucide-react";
import { Badge } from "./ui/Badge.js";
import { Button } from "./ui/Button.js";
import { Card, CardContent, CardHeader } from "./ui/Card.js";
import { getAssets, getAuthSession, getJson, getOrganizations, postJson } from "../lib/api.js";
import { useOrganizationSelection } from "../lib/organization-selection.js";

type Job = {
  id: string;
  organization_id: string;
  asset_id: string;
  job_state: "queued" | "running" | "succeeded" | "cancelled" | "failed";
  source_format: string | null;
  source_fingerprint: string | null;
  authorization_at: string | null;
  requested_at: string;
  observation_count: number;
  result_coverage: {
    operationCount?: number;
    totalObservations?: number;
    truncated?: boolean;
    limitations?: string[];
  } | null;
};
type Observation = {
  id: string;
  rule_id: string;
  title: string;
  summary: string;
  severity_estimate: string;
  review_state: string;
};
type SavedRun = {
  jobId: string;
  classification: "SPEC_ONLY" | "INVENTORY_ONLY";
  operationCount: number;
  totalObservations: number;
  savedObservations: number;
  networkRequestsSent: 0;
};

const selectClass =
  "h-11 w-full rounded-xl border border-white/10 bg-slate-950/70 px-3 text-sm text-white outline-none focus:border-cyan-300/60";
const labelClass = "mb-1.5 block text-xs font-medium text-slate-300";

function isCurrentlyVerified(asset: CustomerAsset) {
  return asset.verification_status === "verified" && asset.verification_expires_at !== null
    && Date.parse(asset.verification_expires_at) > Date.now();
}

/**
 * Explicit consent for an owned API asset; hosted verification and backend-only
 * service key must both be ready or the server refuses to persist a run.
 */
export function SavedAssessmentsPanel() {
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [assetId, setAssetId] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState("");
  const session = useQuery({ queryKey: ["auth-session"], queryFn: getAuthSession });
  const organizationsQuery = useQuery({ queryKey: ["organizations"], queryFn: getOrganizations });
  const organizations = organizationsQuery.data?.organizations ?? [];
  const { activeOrganizationId, selectOrganization } = useOrganizationSelection(organizations);
  const role = organizationsQuery.data?.memberships.find(
    (m) => m.organization_id === activeOrganizationId,
  )?.member_role;
  const canSubmit = role === "owner" || role === "admin" || role === "analyst";

  const assets = useQuery({
    queryKey: ["assets", activeOrganizationId],
    queryFn: () => getAssets(activeOrganizationId),
    enabled: Boolean(activeOrganizationId),
  });
  const verifiedApiAssets = (assets.data?.assets ?? []).filter(
    (asset) => asset.asset_kind === "api" && isCurrentlyVerified(asset),
  );
  const selectedAsset = verifiedApiAssets.find((asset) => asset.id === assetId);

  const jobs = useQuery({
    queryKey: ["offline-api-jobs", activeOrganizationId],
    queryFn: () => getJson<{ jobs: Job[] }>(
      "/v1/assessments/api-spec?organizationId=" + encodeURIComponent(activeOrganizationId)),
    enabled: Boolean(activeOrganizationId),
  });
  const observations = useQuery({
    queryKey: ["offline-api-observations", activeOrganizationId, selectedJobId],
    queryFn: () => getJson<{ observations: Observation[] }>(
      "/v1/assessments/api-spec/observations?organizationId="
        + encodeURIComponent(activeOrganizationId) + "&jobId=" + encodeURIComponent(selectedJobId)),
    enabled: Boolean(activeOrganizationId && selectedJobId),
  });
  const submit = useMutation({
    mutationFn: async () => {
      if (!file || !selectedAsset || !activeOrganizationId || !authorized) {
        throw new Error("Choose a currently verified API asset and confirm your authority.");
      }
      if (file.size > 1024 * 1024) throw new Error("The document must be 1 MiB or smaller.");
      return postJson<SavedRun>("/v1/assessments/api-spec", {
        organizationId: activeOrganizationId,
        assetId: selectedAsset.id,
        filename: file.name,
        content: await file.text(),
        authorization: "I_AM_AUTHORIZED_FOR_OFFLINE_SPEC_REVIEW",
      }, session.data?.csrfToken ?? "");
    },
    onSuccess: async (result) => {
      setSelectedJobId(result.jobId);
      await queryClient.invalidateQueries({ queryKey: ["offline-api-jobs", activeOrganizationId] });
    },
  });
  const cancel = useMutation({
    mutationFn: (jobId: string) => postJson<{ cancelled: boolean }>(
      "/v1/assessments/api-spec/cancel",
      { organizationId: activeOrganizationId, jobId },
      session.data?.csrfToken ?? ""),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["offline-api-jobs", activeOrganizationId] });
    },
  });

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-3">
          <Database size={19} className="text-cyan-200" />
          <div>
            <h2 className="font-semibold text-white">Verified-asset assessment history</h2>
            <p className="mt-1 text-xs leading-5 text-slate-400">
              Save a bounded offline specification review to your organization's workspace.
              No API requests are executed, and no raw specification is stored.
            </p>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {organizationsQuery.isError ? (
          <p role="alert" className="text-sm text-rose-300">{organizationsQuery.error.message}</p>
        ) : null}
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label htmlFor="assessment-org" className={labelClass}>Organization</label>
            <select id="assessment-org" className={selectClass} value={activeOrganizationId}
              onChange={(event) => {
                selectOrganization(event.target.value);
                setAssetId("");
                setAuthorized(false);
                setSelectedJobId("");
              }}>
              <option value="">Select organization</option>
              {organizations.map((org) => <option key={org.id} value={org.id}>{org.display_name}</option>)}
            </select>
          </div>
          <div>
            <label htmlFor="assessment-asset" className={labelClass}>Verified API asset</label>
            <select id="assessment-asset" className={selectClass} value={selectedAsset?.id ?? ""}
              disabled={!canSubmit} onChange={(event) => { setAssetId(event.target.value); setAuthorized(false); }}>
              <option value="">Choose verified API asset</option>
              {verifiedApiAssets.map((asset) => (
                <option key={asset.id} value={asset.id}>{asset.display_name} — {asset.canonical_origin}</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/5 p-4 text-xs leading-6 text-amber-100">
          <AlertTriangle size={17} className="mt-1 shrink-0" />
          <p>Verification of ownership is mandatory even for saved offline assessment jobs.
            Only Owner, Admin or existing Analyst roles may submit. Revalidation occurs before execution
            and when results are committed. This is not permission to scan a live service.</p>
        </div>
        {canSubmit ? (
          <div className="space-y-4">
            <label className="block cursor-pointer rounded-xl border border-dashed border-white/15 p-4 text-sm text-slate-300">
              <span className="inline-flex items-center gap-2"><FileCheck2 size={16} /> {file ? file.name : "Choose API specification for saved review"}</span>
              <input type="file" accept=".json,.yaml,.yml,application/json,text/yaml" className="sr-only"
                onChange={(event) => { setFile(event.target.files?.[0] ?? null); setAuthorized(false); }} />
            </label>
            <label className="flex cursor-pointer items-start gap-3 text-xs leading-6 text-slate-300">
              <input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)}
                className="mt-1.5" />
              <span>I am authorized by the asset owner to review this exact API specification offline;
                the selected asset is in my organization's approved scope.</span>
            </label>
            <Button disabled={!selectedAsset || !authorized || !file || submit.isPending || !session.data?.csrfToken}
              onClick={() => submit.mutate()}>
              <LockKeyhole size={16} /> {submit.isPending ? "Reviewing offline…" : "Save authorized offline assessment"}
            </Button>
          </div>
        ) : (
          <p className="text-xs text-slate-400">You can review your organization's saved observations,
            but only authorized management roles can create assessments.</p>
        )}
        {verifiedApiAssets.length === 0 && canSubmit ? (
          <p className="text-xs text-amber-200">No currently verified API asset. Complete a DNS/HTTPS ownership challenge first.</p>
        ) : null}
        {submit.isError ? <p role="alert" className="text-sm text-rose-300">{submit.error.message}</p> : null}
        {submit.data ? (
          <p role="status" className="text-xs text-emerald-200">
            Saved job {submit.data.jobId} · {submit.data.classification} · {submit.data.operationCount} operations ·
            {submit.data.savedObservations} of {submit.data.totalObservations} observations saved · zero network requests.
          </p>
        ) : null}

        <section className="space-y-3">
          <h3 className="text-sm font-semibold text-white">Recent saved assessments</h3>
          {jobs.isError ? <p role="alert" className="text-xs text-rose-300">{jobs.error.message}</p> : null}
          {jobs.isLoading && activeOrganizationId ? <p className="text-xs text-slate-400">Loading tenant history…</p> : null}
          {jobs.data?.jobs.length === 0 ? <p className="text-xs text-slate-400">No saved assessments yet.</p> : null}
          {jobs.data?.jobs.map((job) => (
            <div key={job.id} className="rounded-xl border border-white/10 bg-slate-950/50 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs text-slate-300">{job.source_format ?? "Offline API"} · {new Date(job.requested_at).toLocaleString()}</div>
                <Badge variant={job.job_state === "succeeded" ? "info" : job.job_state === "failed" ? "danger" : "neutral"}>{job.job_state}</Badge>
              </div>
              <p className="mt-2 text-xs text-slate-400">{job.observation_count} saved review observations.
                Coverage and runtime security remain unverified.</p>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button size="sm" variant="secondary" onClick={() => setSelectedJobId(job.id)}>
                  Review evidence
                </Button>
                {canSubmit && ["queued", "running"].includes(job.job_state) ? (
                  <Button size="sm" variant="secondary" disabled={cancel.isPending}
                    onClick={() => cancel.mutate(job.id)}>Cancel job</Button>
                ) : null}
              </div>
            </div>
          ))}
          {cancel.isError ? <p role="alert" className="text-xs text-rose-300">{cancel.error.message}</p> : null}
        </section>

        {selectedJobId ? (
          <section className="space-y-3" aria-label="Saved assessment evidence">
            <h3 className="text-sm font-semibold text-white">Review-only evidence</h3>
            {observations.isLoading ? <p className="text-xs text-slate-400">Loading evidence…</p> : null}
            {observations.isError ? <p role="alert" className="text-xs text-rose-300">{observations.error.message}</p> : null}
            {observations.data?.observations.length === 0 ? (
              <p className="text-xs text-slate-400">No observations stored for this job; absence is not proof of API security.</p>
            ) : null}
            {observations.data?.observations.map((item) => (
              <div key={item.id} className="rounded-xl border border-white/10 p-4">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-semibold text-slate-100">{item.rule_id}</span>
                  <Badge>{item.severity_estimate}</Badge>
                  <Badge>{item.review_state}</Badge>
                </div>
                <p className="mt-2 whitespace-pre-wrap text-xs leading-6 text-slate-300">{item.summary}</p>
              </div>
            ))}
          </section>
        ) : null}
      </CardContent>
    </Card>
  );
}
