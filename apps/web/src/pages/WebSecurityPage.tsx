import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Activity, FileCheck2, LockKeyhole, ShieldAlert, Globe2 } from "lucide-react";
import { Badge } from "../components/ui/Badge.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent, CardHeader } from "../components/ui/Card.js";
import type { CustomerAsset } from "@lumicsec/shared";
import { getAssets, getAuthSession, getJson, getOrganizations, postJson } from "../lib/api.js";
import { useOrganizationSelection } from "../lib/organization-selection.js";

const fieldClass = "mb-1.5 block text-xs font-medium text-slate-300";
const selectClass = "h-11 w-full rounded-xl border border-white/10 bg-slate-950/70 px-3 text-sm text-white";
const scanningEnabled = false as const;

type WebJob = {
  id: string; organization_id: string; asset_id: string; job_state: string; scope_hash: string;
  requested_at: string; started_at: string | null; completed_at: string | null;
  authorization_at: string | null; web_origin: string;
  observation_count: number; web_error_code: string | null;
  web_report: {
    classification?: string; requests?: number; fetched?: number; bytes?: number;
    failed?: number; coverageState?: string; limitations?: string[];
    candidateCount?: number; snapshotFingerprint?: string;
  } | null;
};
type WebObservation = {
  id: string; rule_id: string; title: string; summary: string; severity_estimate: string;
  observation_classification: string; remediation: string | null; limitation: string | null;
  evidence_source: { nodeIds?: string[]; fingerprints?: string[]; paths?: string[] } | null; review_state: string;
};

function currentWebsite(asset: CustomerAsset) {
  return asset.asset_kind === "website" && asset.verification_status === "verified" &&
    !!asset.verification_expires_at && Date.parse(asset.verification_expires_at) > Date.now();
}

export function WebSecurityPage() {
  const queryClient = useQueryClient();
  const [assetId, setAssetId] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState("");
  const session = useQuery({ queryKey: ["auth-session"], queryFn: getAuthSession });
  const orgQuery = useQuery({ queryKey: ["organizations"], queryFn: getOrganizations });
  const organizations = orgQuery.data?.organizations ?? [];
  const { activeOrganizationId, selectOrganization } = useOrganizationSelection(organizations);
  const role = orgQuery.data?.memberships.find(m => m.organization_id === activeOrganizationId)?.member_role;
  const canControl = role === "owner" || role === "admin" || role === "analyst";
  const assetsQuery = useQuery({
    queryKey: ["assets", activeOrganizationId], queryFn: () => getAssets(activeOrganizationId),
    enabled: Boolean(activeOrganizationId),
  });
  const websites = (assetsQuery.data?.assets ?? []).filter(currentWebsite);
  const selected = websites.find(asset => asset.id === assetId);
  const jobs = useQuery({
    queryKey: ["web-jobs", activeOrganizationId],
    queryFn: () => getJson<{ jobs: WebJob[]; scanningEnabled: false }>(
      "/v1/assessments/web?organizationId=" + encodeURIComponent(activeOrganizationId)),
    enabled: Boolean(activeOrganizationId),
  });
  const evidence = useQuery({
    queryKey: ["web-evidence", activeOrganizationId, selectedJobId],
    queryFn: () => getJson<{ observations: WebObservation[] }>(
      "/v1/assessments/web/observations?organizationId=" +
      encodeURIComponent(activeOrganizationId) + "&jobId=" + encodeURIComponent(selectedJobId)),
    enabled: Boolean(activeOrganizationId && selectedJobId),
  });
  const cancel = useMutation({
    mutationFn: (jobId: string) => postJson<{ cancelled: boolean }>(
      "/v1/assessments/web/cancel", { organizationId: activeOrganizationId, jobId },
      session.data?.csrfToken ?? ""),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["web-jobs", activeOrganizationId] });
    },
  });

  return <div className="space-y-7">
    <section>
      <div className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-200">Website security</div>
      <h1 className="mt-2 text-3xl font-semibold text-white">Authorized passive Web assessments</h1>
      <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">
        Review real captured passive security observations by organization and verified website.
        Evidence remains classified for manual review; these signals are not confirmed exploitable vulnerabilities.
      </p>
    </section>
    <div role="status" className="rounded-xl border border-amber-300/30 bg-amber-300/5 p-4 text-sm text-amber-100">
      Customer network scanning is <strong>not activated</strong>. The isolated worker is being
      qualified against controlled synthetic HTTPS websites only. This screen cannot start a public scan.
    </div>
    <Card>
      <CardHeader className="flex items-center gap-3">
        <LockKeyhole size={19} className="text-cyan-200" />
        <div>
          <h2 className="font-semibold text-white">Asset → explicit scope → assessment</h2>
          <p className="text-xs text-slate-400">A current ownership proof and authorization are both mandatory.</p>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div><label htmlFor="web-assessment-org" className={fieldClass}>Organization</label>
            <select id="web-assessment-org" className={selectClass} value={activeOrganizationId}
              onChange={e => { selectOrganization(e.target.value); setAssetId(""); setSelectedJobId(""); setAuthorized(false); }}>
              <option value="">Choose organization</option>
              {organizations.map(o => <option key={o.id} value={o.id}>{o.display_name}</option>)}
            </select>
          </div>
          <div><label htmlFor="web-assessment-asset" className={fieldClass}>Currently verified website</label>
            <select id="web-assessment-asset" className={selectClass} value={selected?.id ?? ""}
              disabled={!canControl} onChange={e => { setAssetId(e.target.value); setAuthorized(false); }}>
              <option value="">Choose verified website</option>
              {websites.map(a => <option key={a.id} value={a.id}>{a.display_name} — {a.canonical_origin}</option>)}
            </select>
          </div>
        </div>
        {selected ? <p className="text-xs text-cyan-200">
          Exact permitted HTTPS origin: <strong>{selected.canonical_origin}</strong>
          {" "}· GET-only · at most six requests · 240 KB total · one concurrent request.
        </p> : null}
        {canControl ? <>
          {websites.length === 0 && activeOrganizationId ?
            <p role="status" className="text-xs text-amber-200">
              No currently verified website in this organization. Complete DNS/HTTPS asset ownership first.
            </p> : null}
          <label className="flex items-start gap-3 text-sm text-slate-300">
            <input type="checkbox" checked={authorized} className="mt-1" disabled={!selected}
              onChange={e => setAuthorized(e.target.checked)} />
            <span>I have explicit written permission from this website's owner for a
              bounded read-only security assessment of this exact origin.
              Ownership verification alone is not scanning authorization.</span>
          </label>
          <Button disabled={!scanningEnabled || !selected || !authorized || !session.data?.csrfToken}>
            <ShieldAlert size={16} /> Start authorized Web assessment (disabled)
          </Button>
        </> : <p className="text-xs text-slate-400">
          This role can review stored observations, but cannot authorize or cancel assessments.
        </p>}
      </CardContent>
    </Card>
    <Card>
      <CardHeader className="flex items-center gap-3"><Activity size={18} className="text-cyan-200" />
        <div><h2 className="font-semibold text-white">Assessment jobs and retained evidence</h2>
          <p className="text-xs text-slate-400">Tenant-isolated database history. No raw HTTP bodies or secrets stored.</p></div>
      </CardHeader>
      <CardContent className="space-y-4">
        {jobs.isLoading && activeOrganizationId ?
          <p className="text-sm text-slate-400">Loading organization assessments…</p> : null}
        {jobs.isError ? <p role="alert" className="text-sm text-rose-300">{jobs.error.message}</p> : null}
        {jobs.data?.jobs.length === 0 ? <p className="text-sm text-slate-400">No saved website assessments yet.</p> : null}
        {jobs.data?.jobs.map(job => <div key={job.id}
          className="rounded-xl border border-white/10 bg-slate-950/50 p-4">
          <div className="flex flex-wrap justify-between gap-3 text-xs text-slate-200">
            <span><Globe2 size={13} className="mr-1 inline" /> {job.web_origin}</span>
            <Badge>{job.job_state}</Badge>
          </div>
          <p className="mt-2 text-xs text-slate-400">
            {new Date(job.requested_at).toLocaleString()} · {job.observation_count} review observations
            {job.web_report ? " · " + (job.web_report.fetched ?? 0) + " HTTPS responses inspected" : ""}
          </p>
          {job.web_report ? <p className="mt-1 text-xs text-slate-500">
            Coverage: {job.web_report.coverageState ?? "unknown"}, {job.web_report.requests ?? 0} requests,
            {" "}{job.web_report.bytes ?? 0} bytes. No exploit validation.</p> : null}
          <div className="mt-3 flex flex-wrap gap-2">
            <Button variant="secondary" size="sm" onClick={() => setSelectedJobId(job.id)}>
              <FileCheck2 size={14} /> Review evidence
            </Button>
            {canControl && ["queued", "running"].includes(job.job_state) ?
              <Button variant="secondary" size="sm" disabled={cancel.isPending || !session.data?.csrfToken}
                onClick={() => cancel.mutate(job.id)}>Cancel assessment</Button> : null}
          </div>
        </div>)}
        {cancel.isError ? <p role="alert" className="text-xs text-rose-300">{cancel.error.message}</p> : null}
      </CardContent>
    </Card>
    {selectedJobId ? <Card>
      <CardHeader><h2 className="font-semibold text-white">Evidence and remediation review</h2>
        <p className="text-xs text-slate-400">Rule identifiers reference captured passive signals,
          not verified exploitability or a pentest certification.</p></CardHeader>
      <CardContent className="space-y-3">
        {evidence.isLoading ? <p className="text-xs text-slate-400">Loading observations…</p> : null}
        {evidence.isError ? <p role="alert" className="text-xs text-rose-300">{evidence.error.message}</p> : null}
        {evidence.data?.observations.length === 0 ? <p className="text-xs text-slate-400">
          No review observations recorded. This does not establish that the website is secure.</p> : null}
        {evidence.data?.observations.map(item => <div key={item.id}
          className="rounded-xl border border-white/10 p-4 text-xs leading-6 text-slate-300">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-white">{item.rule_id}</span>
            <Badge>{item.severity_estimate}</Badge><Badge>{item.review_state}</Badge>
          </div>
          <p className="mt-1 font-medium text-slate-100">{item.title}</p>
          <p className="mt-1">Observed signal: {item.observation_classification}</p>
          <p className="mt-1">{item.summary}</p>
          <p className="mt-2 text-cyan-200">Remediation: {item.remediation ?? "Review the source configuration."}</p>
          <p className="mt-1 text-amber-200">Limitation: {item.limitation ?? "Passive observation only."}</p>
          <p className="mt-2 text-slate-400">
            Observed HTTPS paths: {item.evidence_source?.paths?.slice(0, 3).join(", ") || "Not retained"}
          </p>
          <p className="mt-1 break-all text-slate-500">
            Source fingerprints: {item.evidence_source?.fingerprints?.slice(0, 4).join(", ") ?? "Not available"}
          </p>
        </div>)}
      </CardContent>
    </Card> : null}
  </div>;
}
