import { useMutation, useQueryClient } from "@tanstack/react-query";
import { zodResolver } from "@hookform/resolvers/zod";
import { LockKeyhole, ShieldCheck } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import type { AuthSessionResponse } from "@lumicsec/shared";
import { mfaCodeSchema } from "@lumicsec/validation";
import { postJson } from "../lib/api.js";
import { Button } from "../components/ui/Button.js";
import { Card, CardContent } from "../components/ui/Card.js";
import { Input } from "../components/ui/Input.js";

const formSchema = z.object({ code: mfaCodeSchema });

export function MfaChallengePage({ session }: { session: AuthSessionResponse }) {
  const queryClient = useQueryClient();
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

  return (
    <main className="grid min-h-screen place-items-center bg-[#080d19] px-5 py-10 text-slate-100">
      <Card className="w-full max-w-md">
        <CardContent className="p-8">
          <div className="grid h-12 w-12 place-items-center rounded-xl bg-cyan-300/10 text-cyan-200"><LockKeyhole size={22} /></div>
          <div className="mt-5 text-xs uppercase tracking-[0.2em] text-cyan-200">AAL2 verification</div>
          <h1 className="mt-2 text-2xl font-semibold text-white">Verify your authenticator</h1>
          <p className="mt-3 text-sm leading-6 text-slate-400">Enter the current six-digit code from your registered authenticator app to open the protected workspace.</p>
          <form className="mt-7 space-y-3" onSubmit={form.handleSubmit((values) => verify.mutate(values.code))}>
            <label className="block text-sm font-medium text-slate-200" htmlFor="totp-challenge">Authenticator code</label>
            <Input id="totp-challenge" inputMode="numeric" autoComplete="one-time-code" maxLength={6} placeholder="000000" {...form.register("code")} />
            {form.formState.errors.code ? <p className="text-xs text-rose-300">{form.formState.errors.code.message}</p> : null}
            {verify.isError ? <p className="text-xs text-rose-300">{verify.error.message}</p> : null}
            <Button className="w-full" type="submit" disabled={verify.isPending}><ShieldCheck size={16} /> {verify.isPending ? "Verifying…" : "Verify and continue"}</Button>
          </form>
          <p className="mt-5 text-center text-[11px] leading-5 text-slate-500">Protected product routes remain blocked until Supabase confirms AAL2.</p>
        </CardContent>
      </Card>
    </main>
  );
}
