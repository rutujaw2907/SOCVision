import { cn } from "@/lib/utils";
import { normalizeSeverity, type Severity } from "@/types/soc";

const styles: Record<Severity, string> = {
  critical: "bg-critical-soft text-critical border-critical/40",
  high: "bg-high-soft text-high border-high/40",
  medium: "bg-medium-soft text-medium border-medium/40",
  low: "bg-low-soft text-low border-low/40",
};

export const severityColorVar: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
  low: "var(--low)",
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: string | null | undefined;
  className?: string;
}) {
  const level = normalizeSeverity(severity);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[11px] font-medium tracking-wider uppercase",
        styles[level],
        className,
      )}
    >
      <span
        aria-hidden
        className="size-1.5 rounded-full"
        style={{ backgroundColor: severityColorVar[level] }}
      />
      {level}
    </span>
  );
}
