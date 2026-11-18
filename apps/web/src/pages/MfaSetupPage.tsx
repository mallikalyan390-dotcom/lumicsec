import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { KeyRound, QrCode, ShieldCheck } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import type { AuthSessionResponse } from "@lumicsec/shared";
import { isTrustedTotpPngDataUrl, isTrustedTotpQrImageDataUrl, mfaCodeSchema } from "@lumicsec/validation";
import { postJson } from "../lib/api.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent } from "../components/ui/Card.js";
import { Input } from "../components/ui/Input.js";

const formSchema = z.object({ code: mfaCodeSchema });
type Enrollment = { qrCodePng?: string | null; qrCodeSvg: string | null; secret: string };

export function MfaSetupPage({ session }: { session: AuthSessionResponse }) {
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [qrFailed, setQrFailed] = useState(false);
  const queryClient = useQueryClient();
  const enroll = useMutation({
    mutationFn: () => postJson<Enrollment>("/auth/mfa/enroll", {}, session.csrfToken),
    onSuccess: (value) => {
      setQrFailed(false);
      setEnrollment(value);
      form.reset();
    },
  });
  const verify = useMutation({
    mutationFn: (code: string) => postJson<{ verified: boolean }>("/auth/mfa/verify", { code }, session.csrfToken),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["auth-session"] });
    },
  });
  const form = useForm<z.infer<typeof formSchema>>({
    resolver: zodResolver(formSchema),
    defaultValues: { code: "" },
  });

  // Prefer locally generated PNG: no Supabase SVG dependency in the browser.
  // Retain the hardened SVG path as a compatibility fallback only.
  const pngSource = enrollment?.qrCodePng ?? "";
  const svgSource = enrollment?.qrCodeSvg ?? "";
  const qrSource = isTrustedTotpPngDataUrl(pngSource) ? pngSource : svgSource;
  const qrValid = isTrustedTotpPngDataUrl(qrSource) || isTrustedTotpQrImageDataUrl(qrSource);

  return (
    <main className="grid min-h-screen place-items-center bg-[#080d19] px-5 py-10 text-slate-100">
      <Card className="w-full max-w-xl">
        <CardContent className="p-7 sm:p-9">
          <div className="flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-xl bg-cyan-300/10 text-cyan-200"><ShieldCheck size={22} /></div><div><div className="text-xs uppercase tracking-[0.2em] text-cyan-200">Required security step</div><h1 className="mt-1 text-2xl font-semibold text-white">Set up your authenticator</h1></div></div>
          <p className="mt-5 text-sm leading-6 text-slate-400">Scan the QR code with Google Authenticator, Microsoft Authenticator, Authy or 1Password. Enter the six-digit code to verify enrollment.</p>

          {!enrollment ? (
            <Button className="mt-7 w-full" onClick={() => enroll.mutate()} disabled={enroll.isPending}>
              <QrCode size={16} /> {enroll.isPending ? "Preparing QR code…" : "Create authenticator"}
            </Button>
          ) : (
            <div className="mt-7 grid gap-6 sm:grid-cols-[180px_1fr]">
              <div className="grid min-h-44 place-items-center rounded-2xl bg-white p-3">
                {qrValid && !qrFailed
                  ? <img src={qrSource} alt="Authenticator enrollment QR code" className="h-40 w-40" onError={() => setQrFailed(true)} />
                  : <p role="alert" className="text-center text-xs text-rose-700">QR image unavailable. Enter the manual setup key in your authenticator, then verify below, or generate a fresh QR.</p>}
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-400">Manual setup key</div>
                <div className="mt-2 break-all rounded-xl border border-white/10 bg-slate-950 p-3 font-mono text-sm text-cyan-100">{enrollment.secret}</div>
                <p className="mt-2 text-xs leading-5 text-slate-400">If you cannot scan the QR, choose manual entry in your authenticator app, use LumicSec as the account label, and select a time-based (TOTP) code. Enter the generated six-digit code below.</p>
                <p className="mt-2 text-xs leading-5 text-slate-500">Keep this secret private. It is shown only during enrollment and is not written to application logs.</p>
              </div>
            </div>
          )}

          {enrollment ? (
            <Button className="mt-4 w-full" onClick={() => enroll.mutate()} disabled={enroll.isPending || verify.isPending}>
              {enroll.isPending ? "Replacing setup…" : "Discard setup and generate a fresh QR"}
            </Button>
          ) : null}

          {enrollment ? (
            <form className="mt-7 space-y-3" onSubmit={form.handleSubmit((values) => verify.mutate(values.code))}>
              <label className="block text-sm font-medium text-slate-200" htmlFor="totp-code">Six-digit authenticator code</label>
              <Input id="totp-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" {...form.register("code")} />
              {form.formState.errors.code ? <p className="text-xs text-rose-300">{form.formState.errors.code.message}</p> : null}
              {verify.isError ? <p role="alert" className="text-xs text-rose-300">{verify.error.message}</p> : null}
              <Button className="w-full" type="submit" disabled={verify.isPending || enroll.isPending}>{verify.isPending ? "Verifying…" : "Verify and continue"}</Button>
            </form>
          ) : null}

          {enroll.isError ? <p role="alert" className="mt-4 text-xs text-rose-300">{enroll.error.message}</p> : null}
          {enrollment ? <p className="mt-3 text-xs text-slate-400">If this setup was previously displayed, abandoned or exposed, do not reuse it. Refreshing the page and choosing Create authenticator replaces the previous unverified LumicSec factor. Never share this QR or manual key.</p> : null}
          <div className="mt-6 flex items-start gap-2 rounded-xl border border-amber-400/20 bg-amber-400/5 p-3 text-xs leading-5 text-amber-100">
            <KeyRound size={15} className="mt-0.5 shrink-0" />
            <span>Single-use recovery codes are not available yet. Do not use this build for production accounts until the custom recovery-code milestone is complete. Registering a second authenticator factor is planned.</span>
          </div>
        </CardContent>
      </Card>
    </main>
  );
}
