import type { HTMLAttributes } from "react";
import { cn } from "../../lib/utils.js";

type BadgeVariant = "neutral" | "success" | "warning" | "danger" | "info";

const variants: Record<BadgeVariant, string> = {
  neutral: "border-white/10 bg-white/5 text-slate-300",
  success: "border-emerald-400/20 bg-emerald-400/10 text-emerald-200",
  warning: "border-amber-400/20 bg-amber-400/10 text-amber-200",
  danger: "border-rose-400/20 bg-rose-400/10 text-rose-200",
  info: "border-cyan-400/20 bg-cyan-400/10 text-cyan-200",
};

export function Badge({ variant = "neutral", className, ...props }: HTMLAttributes<HTMLSpanElement> & { variant?: BadgeVariant }) {
  return <span className={cn("inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold tracking-wide", variants[variant], className)} {...props} />;
}
