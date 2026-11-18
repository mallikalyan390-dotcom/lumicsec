import { ShieldCheck, LockKeyhole } from "lucide-react";
import type { AuthSessionResponse } from "@lumicsec/shared";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent } from "../components/ui/Card.js";

export function LoginPage({ session }: { session: AuthSessionResponse }) {
  const authError = new URLSearchParams(window.location.search).get("authError");

  return (
    <main className="relative grid min-h-screen overflow-hidden bg-[#080d19] px-5 py-12 text-slate-100 lg:grid-cols-[1.1fr_0.9fr] lg:px-16">
      <div className="pointer-events-none absolute -left-32 -top-32 h-96 w-96 rounded-full bg-cyan-400/10 blur-3xl" />
      <section className="relative flex flex-col justify-center py-10">
        <div className="flex items-center gap-3">
          <div className="grid h-12 w-12 place-items-center rounded-2xl bg-cyan-300 text-slate-950"><ShieldCheck size={25} /></div>
          <div>
            <div className="text-2xl font-bold tracking-tight text-white">LumicSec</div>
            <div className="text-[10px] uppercase tracking-[0.25em] text-slate-500">Web & API security</div>
          </div>
        </div>
        <h1 className="mt-16 max-w-2xl text-4xl font-semibold leading-tight tracking-tight text-white sm:text-5xl">
          Security clarity for the systems you build.
        </h1>
        <p className="mt-6 max-w-xl text-base leading-8 text-slate-400">
          A unified workspace for authorized website and API assessment, evidence review and remediation.
        </p>
        <div className="mt-10 flex flex-wrap gap-3 text-xs text-slate-400">
          <span className="rounded-full border border-white/10 px-3 py-2">Evidence-led assessments</span>
          <span className="rounded-full border border-white/10 px-3 py-2">Tenant-aware security</span>
          <span className="rounded-full border border-white/10 px-3 py-2">Google OAuth + TOTP</span>
        </div>
      </section>

      <section className="relative flex items-center justify-center py-10">
        <Card className="w-full max-w-md border-white/10 bg-slate-900/80">
          <CardContent className="p-8">
            <div className="flex items-center gap-2 text-sm font-semibold text-white"><LockKeyhole size={17} className="text-cyan-300" /> Secure sign in</div>
            <h2 className="mt-5 text-2xl font-semibold text-white">Welcome to LumicSec</h2>
            <p className="mt-2 text-sm leading-6 text-slate-400">Continue with Google. Every account must register and verify an authenticator before entering the workspace.</p>
            {authError ? <p className="mt-4 rounded-xl border border-rose-400/20 bg-rose-400/10 p-3 text-xs text-rose-200">Google sign-in could not be completed. Check the Supabase Google provider and redirect allowlist.</p> : null}
            {!session.configured ? (
              <p className="mt-6 rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-xs leading-5 text-amber-100">
                Supabase is not configured. Add the project URL and publishable key to the server .env file, then enable Google OAuth in Supabase Auth.
              </p>
            ) : null}
            <Button className="mt-7 w-full" size="lg" disabled={!session.configured} onClick={() => window.location.assign("/auth/google")}>
              Continue with Google
            </Button>
            <div className="mt-5 text-center text-[11px] leading-5 text-slate-500">
              No password, email OTP, phone/SMS or other social sign-in methods are offered.
            </div>
          </CardContent>
        </Card>
      </section>
    </main>
  );
}
