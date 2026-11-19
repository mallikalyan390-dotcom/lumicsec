import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, FileSearch, FileUp, ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { ApiSpecAssessmentResponse } from "@lumicsec/shared";
import { MAX_SPEC_BYTES } from "@lumicsec/validation";
import { Badge } from "../components/ui/Badge.js";
import { SavedAssessmentsPanel } from "../components/SavedAssessmentsPanel.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent, CardHeader } from "../components/ui/Card.js";
import { getAuthSession, postJson } from "../lib/api.js";

function impactVariant(impact: string): "neutral" | "warning" | "danger" | "info" {
  if (impact === "HIGH" || impact === "CRITICAL") return "danger";
  if (impact === "MEDIUM") return "warning";
  if (impact === "LOW") return "info";
  return "neutral";
}

export function ApiSecurityPage() {
  const session = useQuery({ queryKey: ["auth-session"], queryFn: getAuthSession });
  const [file, setFile] = useState<File | null>(null);
  const assessment = useMutation({
    mutationFn: async (selected: File) => {
      if (selected.size > MAX_SPEC_BYTES) {
        throw new Error("The specification must be 1 MiB or smaller.");
      }
      const content = await selected.text();
      return postJson<ApiSpecAssessmentResponse>(
        "/v1/api-specs/assess",
        { content, filename: selected.name },
        session.data?.csrfToken ?? "",
      );
    },
  });

  const run = () => {
    if (file) assessment.mutate(file);
  };

  return (
    <div className="space-y-7">
      <section>
        <div className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-200">API security</div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Specification assessment</h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">Import an OpenAPI or Swagger document to inventory operations and review deterministic security observations. The document is processed offline and is not saved.</p>
      </section>

      <SavedAssessmentsPanel />

      <Card>
        <CardHeader className="flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-300/10 text-cyan-200"><FileUp size={19} /></div>
          <div><h2 className="font-semibold text-white">Import specification</h2><p className="mt-1 text-xs text-slate-500">JSON or YAML, maximum 1 MiB. External references are rejected.</p></div>
        </CardHeader>
        <CardContent>
          <label className="flex min-h-32 cursor-pointer flex-col items-center justify-center rounded-2xl border border-dashed border-white/15 bg-slate-950/40 px-4 py-6 text-center hover:border-cyan-300/40">
            <FileSearch size={24} className="text-cyan-200" />
            <span className="mt-3 text-sm font-medium text-slate-200">{file ? file.name : "Choose an OpenAPI / Swagger file"}</span>
            <span className="mt-1 text-xs text-slate-500">.json, .yaml or .yml</span>
            <input className="sr-only" type="file" accept=".json,.yaml,.yml,application/json,text/yaml" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
          </label>
          <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
            <div className="text-xs text-slate-500">{file ? (file.size.toLocaleString() + " bytes selected") : "No file selected"}</div>
            <Button onClick={run} disabled={!file || assessment.isPending || !session.data?.csrfToken}>
              <ShieldCheck size={16} /> {assessment.isPending ? "Assessing offline…" : "Assess specification"}
            </Button>
          </div>
          {assessment.isError ? <p className="mt-4 text-sm text-rose-300">{assessment.error.message}</p> : null}
        </CardContent>
      </Card>

      {assessment.data ? (
        <div className="space-y-5">
          <Card>
            <CardHeader className="flex flex-wrap items-center justify-between gap-3">
              <div><h2 className="font-semibold text-white">Assessment result</h2><p className="mt-1 text-xs text-slate-500">Transient result; not persisted to a customer workspace.</p></div>
              <Badge variant={assessment.data.classification === "SPEC_ONLY" ? "warning" : "neutral"}>{assessment.data.classification}</Badge>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-3">
              <div><div className="text-xs text-slate-500">Format</div><div className="mt-1 font-semibold text-white">{assessment.data.source.format}</div></div>
              <div><div className="text-xs text-slate-500">Operations</div><div className="mt-1 font-semibold text-white">{assessment.data.operationCount}</div></div>
              <div><div className="text-xs text-slate-500">Observations</div><div className="mt-1 font-semibold text-white">{assessment.data.findings.length}</div></div>
            </CardContent>
          </Card>

          <div className="flex items-start gap-3 rounded-xl border border-amber-400/20 bg-amber-400/5 p-4 text-xs leading-5 text-amber-100">
            <AlertTriangle size={17} className="mt-0.5 shrink-0" />
            <span>SPEC_ONLY observations describe the API document, not verified runtime vulnerabilities. No request was sent to the API. Human review is required.</span>
          </div>

          <section className="space-y-3">
            <h2 className="font-semibold text-white">Security observations</h2>
            {assessment.data.findings.length === 0 ? (
              <Card><CardContent className="text-sm leading-6 text-slate-400">No deterministic specification observations were produced. This does not prove that the API is secure or that runtime controls are correct.</CardContent></Card>
            ) : assessment.data.findings.map((finding, index) => (
              <Card key={finding.ruleId + ":" + index}>
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-semibold text-white">{finding.ruleId}</div>
                    <div className="flex gap-2"><Badge variant={impactVariant(finding.impact)}>{finding.impact}</Badge><Badge>{finding.validationLevel}</Badge></div>
                  </div>
                  <div className="text-xs text-slate-500">{finding.category}{finding.operationKey ? " · " + finding.operationKey : ""} · Review required</div>
                  <p className="text-sm leading-6 text-slate-300">{finding.explanation}</p>
                  <div className="rounded-xl bg-slate-950/70 p-3"><div className="text-[10px] font-semibold uppercase tracking-wide text-cyan-200">Suggested review</div><p className="mt-1 text-xs leading-5 text-slate-400">{finding.remediation}</p></div>
                </CardContent>
              </Card>
            ))}
          </section>

          {assessment.data.limitations.length > 0 ? (
            <Card><CardHeader><h2 className="font-semibold text-white">Coverage limitations</h2></CardHeader><CardContent><ul className="list-disc space-y-2 pl-5 text-xs leading-5 text-slate-400">{assessment.data.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></CardContent></Card>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
