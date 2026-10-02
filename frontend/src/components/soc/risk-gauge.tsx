import { cn } from "@/lib/utils";
import { severityFromScore } from "@/types/soc";
import { severityColorVar } from "./severity-badge";

interface RiskGaugeProps {
  score: number;
  size?: number;
  label?: string;
  className?: string;
}

/** Reusable circular risk-score gauge (0-100). */
export function RiskGauge({ score, size = 132, label = "Risk Score", className }: RiskGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score ?? 0)));
  const severity = severityFromScore(clamped);
  const color = severityColorVar[severity];
  const stroke = size / 11;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;

  return (
    <div className={cn("flex flex-col items-center gap-2", className)}>
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--border)"
            strokeWidth={stroke}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference - (clamped / 100) * circumference}
            className="transition-[stroke-dashoffset] duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-semibold" style={{ color }}>
            {clamped}
          </span>
          <span className="text-[10px] tracking-widest text-muted-foreground uppercase">
            {severity}
          </span>
        </div>
      </div>
      <span className="text-xs text-muted-foreground">{label}</span>
    </div>
  );
}

/** Compact horizontal variant for tables and lists. */
export function RiskBar({ score, className }: { score: number; className?: string }) {
  const clamped = Math.max(0, Math.min(100, Math.round(score ?? 0)));
  const color = severityColorVar[severityFromScore(clamped)];
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${clamped}%`, backgroundColor: color }}
        />
      </div>
      <span className="font-mono text-xs text-foreground">{clamped}</span>
    </div>
  );
}
