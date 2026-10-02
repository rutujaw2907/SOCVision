import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export function StatCard({
  label,
  value,
  icon: Icon,
  hint,
  accent,
}: {
  label: string;
  value: number | string;
  icon: LucideIcon;
  hint?: string;
  accent?: string;
}) {
  return (
    <div className="panel p-4 transition-colors hover:border-primary/40">
      <div className="flex items-start justify-between">
        <p className="text-[11px] tracking-wider text-muted-foreground uppercase">{label}</p>
        <Icon className="size-4" style={accent ? { color: accent } : undefined} />
      </div>
      <p
        className={cn("mt-3 font-mono text-2xl font-semibold")}
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </p>
      {hint ? <p className="mt-1 text-[11px] text-muted-foreground">{hint}</p> : null}
    </div>
  );
}
