import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { getAuthSession } from "../lib/api.js";
import { AppShell } from "./AppShell.js";
import { LoginPage } from "../pages/LoginPage.js";
import { MfaChallengePage } from "../pages/MfaChallengePage.js";
import { MfaSetupPage } from "../pages/MfaSetupPage.js";

export function AuthGate({ children }: { children: ReactNode }) {
  const sessionQuery = useQuery({
    queryKey: ["auth-session"],
    queryFn: getAuthSession,
    retry: false,
  });

  if (sessionQuery.isLoading) {
    return <div className="grid min-h-screen place-items-center text-sm text-slate-400">Loading secure session…</div>;
  }

  if (sessionQuery.isError || !sessionQuery.data) {
    return (
      <div className="grid min-h-screen place-items-center px-6">
        <div className="max-w-md text-center">
          <h1 className="text-xl font-semibold text-white">LumicSec is unavailable</h1>
          <p className="mt-2 text-sm text-slate-400">The API could not confirm your session. Check the local API service and retry.</p>
          <button className="mt-5 rounded-xl bg-cyan-300 px-4 py-2 text-sm font-semibold text-slate-950" onClick={() => void sessionQuery.refetch()}>Retry</button>
        </div>
      </div>
    );
  }

  const session = sessionQuery.data;

  if (session.state === "unconfigured" || session.state === "anonymous") {
    return <LoginPage session={session} />;
  }

  if (session.state === "needs_enrollment") {
    return <MfaSetupPage session={session} />;
  }

  if (session.state === "needs_challenge") {
    return <MfaChallengePage session={session} />;
  }

  return <AppShell session={session}>{children}</AppShell>;
}
