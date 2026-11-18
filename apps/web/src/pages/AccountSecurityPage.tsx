import { useQuery } from "@tanstack/react-query";
import { KeyRound, ShieldCheck, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { Badge } from "../components/ui/Badge.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent, CardHeader } from "../components/ui/Card.js";
import { getAuthSession, getVerifiedTotpFactors } from "../lib/api.js";
import { MfaSetupPage } from "./MfaSetupPage.js";

export function AccountSecurityPage() {
  const [addingBackup, setAddingBackup] = useState(false);
  const session = useQuery({ queryKey: ["auth-session"], queryFn: getAuthSession });
  const factors = useQuery({
    queryKey: ["verified-totp-factors"],
    queryFn: getVerifiedTotpFactors,
    enabled: session.data?.state === "authenticated",
    retry: false,
  });

  return (
    <div className="space-y-6">
      <section>
        <div className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-200">Personal account</div>
        <h1 className="mt-2 text-3xl font-semibold text-white">Account security</h1>
        <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">
          Google is the only first-factor login provider. Authenticator verification is mandatory for
          customer workspace access.
        </p>
      </section>

      <Card>
        <CardHeader className="flex items-center gap-3">
          <ShieldCheck size={20} className="text-cyan-200" />
          <div>
            <h2 className="font-semibold text-white">Verified authenticator factors</h2>
            <p className="mt-1 text-xs text-slate-400">
              The server checks Google OAuth plus AAL2 before returning this list.
              Secrets and unverified factors are never returned.
            </p>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {factors.isLoading && <p className="text-sm text-slate-400">Checking verified authenticators…</p>}
          {factors.isError && (
            <p role="alert" className="text-sm text-rose-300">
              Authenticator details are not available: {factors.error.message}
            </p>
          )}
          {factors.isSuccess && factors.data.verifiedTotpFactors.length === 0 && (
            <p className="text-sm text-amber-200">No verified TOTP factors were returned. Re-check your session.</p>
          )}
          {factors.isSuccess && factors.data.verifiedTotpFactors.map((factor, index) => (
            <div key={factor.id} className="flex items-center justify-between rounded-xl border border-white/10 bg-slate-950/45 px-4 py-3">
              <div className="flex items-center gap-3">
                <KeyRound size={17} className="text-cyan-200" />
                <div>
                  <div className="text-sm text-white">{factor.friendlyName}</div>
                  <div className="mt-1 text-xs text-slate-500">Verified authenticator {index + 1}</div>
                </div>
              </div>
              <Badge>Verified</Badge>
            </div>
          ))}
          {!addingBackup && (
            <Button type="button" disabled={!factors.isSuccess || factors.data.verifiedTotpFactors.length === 0
              || factors.data.verifiedTotpFactors.length >= 10}
              onClick={() => setAddingBackup(true)}>
              Add backup authenticator
            </Button>
          )}
          <p className="text-xs leading-6 text-slate-500">
            Adding a backup requires your current verified AAL2 session. Your existing verified
            authenticator will not be removed. Supabase may invalidate other sessions after verification.
          </p>
        </CardContent>
      </Card>

      {addingBackup && session.data?.state === "authenticated" && (
        <div className="space-y-3">
          <Button type="button" size="sm" variant="secondary" onClick={() => setAddingBackup(false)}>
            Close backup enrollment
          </Button>
          <MfaSetupPage
            session={session.data}
            mode="backup"
            onVerified={() => {
              setAddingBackup(false);
              void factors.refetch();
            }}
          />
        </div>
      )}

      <Card>
        <CardContent className="flex items-start gap-3 p-5">
          <ShieldAlert size={20} className="mt-1 shrink-0 text-amber-200" />
          <p className="text-xs leading-6 text-amber-100">
            Single-use recovery codes and lost-device recovery are not implemented. This is a
            backup enrollment milestone, not complete recovery management. Previously exposed
            verified factors must not be removed until an independently tested backup or recovery
            process exists and the account owner explicitly approves rotation.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
