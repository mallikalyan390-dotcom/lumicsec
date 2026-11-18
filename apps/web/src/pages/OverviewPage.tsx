import { useQuery } from "@tanstack/react-query";
import { Activity, FileSearch, Globe2, ShieldCheck } from "lucide-react";
import { getApiHealth } from "../lib/api.js";
import { Badge } from "../components/ui/Badge.js";
import { Card, CardContent, CardHeader } from "../components/ui/Card.js";

export function OverviewPage() {
  const health = useQuery({
    queryKey: ["api-health"],
    queryFn: getApiHealth,
    refetchInterval: 30_000,
  });

  return (
    <div className="space-y-8">
      <section>
        <div className="text-xs font-semibold uppercase tracking-[0.22em] text-cyan-200">Security overview</div>
        <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">Your security workspace</h1>
        <p className="mt-3 max-w-2xl text-sm leading-7 text-slate-400">LumicSec is being brought online in verified stages. The first customer workflow is offline API specification assessment; customer asset scanning is not enabled yet.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-3">
        <Card><CardContent className="flex items-start justify-between p-5"><div><div className="text-xs text-slate-500">API service</div><div className="mt-2 text-lg font-semibold text-white">{health.isSuccess ? "Operational" : health.isLoading ? "Checking…" : "Unavailable"}</div><div className="mt-2 text-xs text-slate-500">Local Fastify health check</div></div><Activity className="text-cyan-200" size={20} /><div className="sr-only">{health.data?.status ?? "unknown"}</div></CardContent></Card>
        <Card><CardContent className="flex items-start justify-between p-5"><div><div className="text-xs text-slate-500">Verified assets</div><div className="mt-2 text-lg font-semibold text-white">Not connected</div><div className="mt-2 text-xs text-slate-500">Ownership and RLS phase pending</div></div><Globe2 className="text-slate-400" size={20} /></CardContent></Card>
        <Card><CardContent className="flex items-start justify-between p-5"><div><div className="text-xs text-slate-500">Available assessment</div><div className="mt-2 text-lg font-semibold text-white">API specification</div><div className="mt-2 text-xs text-slate-500">Offline, SPEC_ONLY</div></div><FileSearch className="text-cyan-200" size={20} /></CardContent></Card>
      </div>

      <Card>
        <CardHeader className="flex flex-wrap items-center justify-between gap-3">
          <div><h2 className="font-semibold text-white">Platform readiness</h2><p className="mt-1 text-xs text-slate-500">Only verified functionality is shown as available.</p></div>
          <Badge variant="warning">Development build</Badge>
        </CardHeader>
        <CardContent className="grid gap-4 md:grid-cols-2">
          <div className="flex gap-3"><ShieldCheck className="mt-0.5 text-emerald-300" size={18} /><div><div className="text-sm font-medium text-slate-200">Google OAuth + TOTP gate</div><p className="mt-1 text-xs leading-5 text-slate-500">Code scaffolded; hosted provider setup, recovery codes and live MFA tests remain pending.</p></div></div>
          <div className="flex gap-3"><FileSearch className="mt-0.5 text-cyan-200" size={18} /><div><div className="text-sm font-medium text-slate-200">Offline API specification engine</div><p className="mt-1 text-xs leading-5 text-slate-500">Imports bounded OpenAPI and Swagger documents. It sends no requests to API servers.</p></div></div>
        </CardContent>
      </Card>
    </div>
  );
}
