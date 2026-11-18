import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FileSearch, Globe2, LayoutDashboard, LogOut, ShieldCheck } from "lucide-react";
import { NavLink, useNavigate } from "react-router";
import type { ReactNode } from "react";
import type { AuthSessionResponse } from "@lumicsec/shared";
import { postJson } from "../lib/api.js";
import { cn } from "../lib/utils.js";
import { Badge } from "./ui/Badge.js";
import { Button } from "./ui/Button.js";

export function AppShell({ session, children }: { session: AuthSessionResponse; children: ReactNode }) {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const logout = useMutation({
    mutationFn: () => postJson<{ signedOut: boolean }>("/auth/logout", {}, session.csrfToken),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["auth-session"] });
      navigate("/", { replace: true });
    },
  });

  const navItems = [
    { to: "/app", label: "Overview", icon: LayoutDashboard, end: true },
    { to: "/app/api-security", label: "API Security", icon: FileSearch, end: false },
    { to: "/app/assets", label: "Assets & organizations", icon: Globe2, end: false },
  ];

  return (
    <div className="min-h-screen bg-[#080d19] text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 border-r border-white/10 bg-slate-950/80 px-4 py-6 backdrop-blur-xl lg:flex lg:flex-col">
        <div className="flex items-center gap-3 px-2">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-300 text-slate-950"><ShieldCheck size={21} /></div>
          <div>
            <div className="text-lg font-bold tracking-tight text-white">LumicSec</div>
            <div className="text-[10px] uppercase tracking-[0.22em] text-slate-500">Security workspace</div>
          </div>
        </div>
        <div className="mt-10 px-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">Workspace</div>
        <nav className="mt-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink key={item.to} to={item.to} end={item.end} className={({ isActive }) => cn(
                "flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition",
                isActive ? "bg-cyan-300/10 text-cyan-200" : "text-slate-400 hover:bg-white/5 hover:text-white",
              )}>
                <Icon size={17} />
                {item.label}
              </NavLink>
            );
          })}
        </nav>
        <div className="mt-8 px-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-500">In development</div>
        <div className="mt-3 space-y-2 px-2 text-xs text-slate-500">
          <div className="flex items-center justify-between"><span>Website Security</span><Badge>Later</Badge></div>
          <div className="flex items-center justify-between"><span>Ownership verification</span><Badge>Later</Badge></div>
          <div className="flex items-center justify-between"><span>Findings & reports</span><Badge>Later</Badge></div>
          <div className="flex items-center justify-between"><span>Monitoring</span><Badge>Later</Badge></div>
        </div>
        <div className="mt-auto rounded-xl border border-white/10 bg-white/[0.03] p-3">
          <div className="text-xs font-semibold text-slate-300">Security gate active</div>
          <div className="mt-1 text-[11px] leading-5 text-slate-500">Protected workspace access requires Google OAuth and verified TOTP AAL2.</div>
        </div>
      </aside>

      <div className="lg:pl-64">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-white/10 bg-[#080d19]/85 px-5 backdrop-blur-xl sm:px-8">
          <div className="flex items-center gap-2 text-sm text-slate-400 lg:hidden"><ShieldCheck size={18} className="text-cyan-300" /> LumicSec</div>
          <div className="hidden text-xs text-slate-500 lg:block">Authorized security workspace</div>
          <div className="flex items-center gap-3">
            <span className="hidden max-w-56 truncate text-xs text-slate-400 sm:block">{session.user?.email ?? "Google account"}</span>
            <Button variant="secondary" size="sm" onClick={() => logout.mutate()} disabled={logout.isPending}>
              <LogOut size={14} /> Sign out
            </Button>
          </div>
        </header>
        <nav className="flex flex-wrap gap-2 border-b border-white/10 px-5 py-3 text-xs lg:hidden" aria-label="Workspace navigation">
          <NavLink to="/app" end className="rounded-lg border border-white/10 px-3 py-2">Overview</NavLink>
          <NavLink to="/app/api-security" className="rounded-lg border border-white/10 px-3 py-2">API Security</NavLink>
          <NavLink to="/app/assets" className="rounded-lg border border-white/10 px-3 py-2">Assets</NavLink>
        </nav>
        <main className="mx-auto max-w-7xl p-5 sm:p-8">{children}</main>
      </div>
    </div>
  );
}
