import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { ArrowUpDown, Search, ShieldAlert } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SeverityBadge } from "./severity-badge";
import { RiskBar } from "./risk-gauge";
import { EmptyState } from "./states";
import { formatTimestamp } from "@/lib/format";
import { normalizeSeverity, type Incident } from "@/types/soc";

type SortKey = "risk" | "timestamp";

export function IncidentsTable({
  incidents,
  pageSize = 10,
  showControls = true,
}: {
  incidents: Incident[];
  pageSize?: number;
  showControls?: boolean;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<string>("all");
  const [sortKey, setSortKey] = useState<SortKey>("timestamp");
  const [desc, setDesc] = useState(true);
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const rows = incidents.filter((incident) => {
      const matchesSeverity =
        severity === "all" || normalizeSeverity(incident.severity) === severity;
      if (!matchesSeverity) return false;
      if (!q) return true;
      return [
        incident.id,
        incident.ip,
        incident.attack,
        incident.endpoint,
        incident.mitre_technique,
        incident.status,
      ]
        .filter(Boolean)
        .some((field) => String(field).toLowerCase().includes(q));
    });

    return [...rows].sort((a, b) => {
      const value =
        sortKey === "risk"
          ? (a.risk_score ?? 0) - (b.risk_score ?? 0)
          : new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
      return desc ? -value : value;
    });
  }, [incidents, query, severity, sortKey, desc]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pageCount - 1);
  const rows = filtered.slice(current * pageSize, current * pageSize + pageSize);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setDesc((d) => !d);
    else {
      setSortKey(key);
      setDesc(true);
    }
  };

  if (incidents.length === 0) {
    return (
      <EmptyState
        title="No security incidents detected"
        description="Incidents will appear here once the SOCVision backend reports detections."
        icon={<ShieldAlert className="size-6" />}
      />
    );
  }

  return (
    <div className="space-y-3">
      {showControls ? (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(0);
              }}
              placeholder="Search by IP, attack, endpoint or technique"
              className="h-9 pl-8 text-sm"
              aria-label="Search incidents"
            />
          </div>
          <Select
            value={severity}
            onValueChange={(v) => {
              setSeverity(v);
              setPage(0);
            }}
          >
            <SelectTrigger className="h-9 w-full sm:w-40" aria-label="Filter by severity">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>
        </div>
      ) : null}

      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full min-w-[920px] text-left text-sm">
          <thead className="bg-muted/40 text-[11px] tracking-wider text-muted-foreground uppercase">
            <tr>
              <th className="px-3 py-2 font-medium">ID</th>
              <th className="px-3 py-2 font-medium">IP Address</th>
              <th className="px-3 py-2 font-medium">Attack</th>
              <th className="px-3 py-2 font-medium">Severity</th>
              <th className="px-3 py-2 font-medium">
                <button
                  className="inline-flex items-center gap-1 uppercase"
                  onClick={() => toggleSort("risk")}
                >
                  Risk Score <ArrowUpDown className="size-3" />
                </button>
              </th>
              <th className="px-3 py-2 font-medium">MITRE</th>
              <th className="px-3 py-2 font-medium">Endpoint</th>
              <th className="px-3 py-2 font-medium">
                <button
                  className="inline-flex items-center gap-1 uppercase"
                  onClick={() => toggleSort("timestamp")}
                >
                  Timestamp <ArrowUpDown className="size-3" />
                </button>
              </th>
              <th className="px-3 py-2 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((incident) => (
              <tr
                key={String(incident.id)}
                className="border-t border-border transition-colors hover:bg-accent/40"
              >
                <td className="px-3 py-2 font-mono text-xs">
                  <Link
                    to="/incidents/$id"
                    params={{ id: String(incident.id) }}
                    className="block text-primary hover:underline"
                  >
                    #{String(incident.id)}
                  </Link>
                </td>
                <td className="px-3 py-2 font-mono text-xs">{incident.ip}</td>
                <td className="px-3 py-2">{incident.attack}</td>
                <td className="px-3 py-2">
                  <SeverityBadge severity={incident.severity} />
                </td>
                <td className="px-3 py-2">
                  <RiskBar score={incident.risk_score} />
                </td>
                <td className="px-3 py-2 font-mono text-xs">{incident.mitre_technique ?? "—"}</td>
                <td className="px-3 py-2 font-mono text-xs">{incident.endpoint ?? "—"}</td>
                <td className="px-3 py-2 text-xs text-muted-foreground">
                  {formatTimestamp(incident.timestamp)}
                </td>
                <td className="px-3 py-2 text-xs">{incident.status ?? "Open"}</td>
              </tr>
            ))}
            {rows.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-3 py-8 text-center text-sm text-muted-foreground">
                  No incidents match the current filters.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </div>

      {showControls && pageCount > 1 ? (
        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <span>
            Page {current + 1} of {pageCount} · {filtered.length} incidents
          </span>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              disabled={current === 0}
              onClick={() => setPage(current - 1)}
            >
              Previous
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={current >= pageCount - 1}
              onClick={() => setPage(current + 1)}
            >
              Next
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
