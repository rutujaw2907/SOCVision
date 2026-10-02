import { useMemo } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  Crosshair,
  Flame,
  Info,
  Network,
  ShieldAlert,
} from "lucide-react";
import { Panel } from "@/components/soc/panel";
import { StatCard } from "@/components/soc/stat-card";
import { SeverityBadge, severityColorVar } from "@/components/soc/severity-badge";
import { IncidentsTable } from "@/components/soc/incidents-table";
import {
  CardSkeletonRow,
  ChartSkeleton,
  EmptyState,
  ErrorState,
  TableSkeleton,
} from "@/components/soc/states";
import { dashboardKeys, fetchStats, fetchTimeline } from "@/services/dashboard";
import { incidentKeys, listIncidents } from "@/services/incidents";
import { formatTimestamp } from "@/lib/format";
import {
  normalizeSeverity,
  type DashboardStats,
  type Incident,
  type MitreActivity,
  type TimelineEvent,
  type TopAttackerIp,
} from "@/types/soc";

export const Route = createFileRoute("/_soc/dashboard")({
  head: () => ({
    meta: [
      { title: "Dashboard — SOCVision" },
      {
        name: "description",
        content: "Real-time security monitoring, severity distribution and threat intelligence.",
      },
      { property: "og:title", content: "Dashboard — SOCVision" },
      {
        property: "og:description",
        content: "Real-time security monitoring, severity distribution and threat intelligence.",
      },
    ],
  }),
  component: DashboardPage,
});

function deriveAttackTypes(stats: DashboardStats | undefined, incidents: Incident[]) {
  if (stats?.attack_types) {
    const raw = stats.attack_types;
    const list = Array.isArray(raw)
      ? raw.map((item) => ({ attack: item.attack, count: item.count }))
      : Object.entries(raw).map(([attack, count]) => ({ attack, count: Number(count) }));
    if (list.length) return list.sort((a, b) => b.count - a.count);
  }
  const map = new Map<string, number>();
  incidents.forEach((incident) => {
    const key = incident.attack || "Other";
    map.set(key, (map.get(key) ?? 0) + 1);
  });
  return [...map.entries()]
    .map(([attack, count]) => ({ attack, count }))
    .sort((a, b) => b.count - a.count);
}

function deriveTopIps(stats: DashboardStats | undefined, incidents: Incident[]): TopAttackerIp[] {
  if (stats?.top_ips?.length) return stats.top_ips;
  const map = new Map<string, { count: number; score: number }>();
  incidents.forEach((incident) => {
    const entry = map.get(incident.ip) ?? { count: 0, score: 0 };
    entry.count += 1;
    entry.score = Math.max(entry.score, incident.risk_score ?? 0);
    map.set(incident.ip, entry);
  });
  return [...map.entries()]
    .map(([ip, value]) => ({ ip, count: value.count, risk_score: value.score }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
}

export function deriveMitre(
  stats: DashboardStats | undefined,
  incidents: Incident[],
): MitreActivity[] {
  if (stats?.mitre?.length) return stats.mitre;
  const map = new Map<string, MitreActivity>();
  incidents.forEach((incident) => {
    const id = incident.mitre_technique;
    if (!id) return;
    const entry = map.get(id) ?? {
      technique: id,
      technique_name: incident.mitre_technique_name ?? incident.attack ?? "Unknown technique",
      attack: incident.attack,
      count: 0,
    };
    entry.count += 1;
    map.set(id, entry);
  });
  return [...map.values()].sort((a, b) => b.count - a.count);
}

function DashboardPage() {
  const statsQuery = useQuery({
    queryKey: dashboardKeys.stats,
    queryFn: ({ signal }) => fetchStats(signal),
    retry: false,
  });
  const incidentsQuery = useQuery({
    queryKey: incidentKeys.list,
    queryFn: ({ signal }) => listIncidents(signal),
    retry: false,
  });
  const timelineQuery = useQuery({
    queryKey: dashboardKeys.timeline,
    queryFn: async ({ signal }) => {
      const data = await fetchTimeline(signal);
      return (Array.isArray(data) ? data : (data?.events ?? [])) as TimelineEvent[];
    },
    retry: false,
  });

  const stats = statsQuery.data;
  const incidents = useMemo(() => incidentsQuery.data ?? [], [incidentsQuery.data]);
  const attackTypes = useMemo(() => deriveAttackTypes(stats, incidents), [stats, incidents]);
  const topIps = useMemo(() => deriveTopIps(stats, incidents), [stats, incidents]);
  const mitre = useMemo(() => deriveMitre(stats, incidents), [stats, incidents]);

  const severityData = [
    { name: "Critical", key: "critical" as const, value: stats?.critical ?? 0 },
    { name: "High", key: "high" as const, value: stats?.high ?? 0 },
    { name: "Medium", key: "medium" as const, value: stats?.medium ?? 0 },
    { name: "Low", key: "low" as const, value: stats?.low ?? 0 },
  ];
  const severityTotal = severityData.reduce((sum, item) => sum + item.value, 0);

  return (
    <div className="space-y-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Security Operations Center</h2>
        <p className="text-sm text-muted-foreground">
          Real-time security monitoring and threat intelligence
        </p>
      </header>

      {statsQuery.isLoading ? (
        <CardSkeletonRow />
      ) : statsQuery.isError ? (
        <ErrorState error={statsQuery.error} onRetry={() => statsQuery.refetch()} />
      ) : (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <StatCard
            label="Total Incidents"
            value={stats?.total_incidents ?? 0}
            icon={ShieldAlert}
            hint="Reported by backend"
          />
          <StatCard
            label="Critical"
            value={stats?.critical ?? 0}
            icon={AlertOctagon}
            accent={severityColorVar.critical}
            hint="Immediate response"
          />
          <StatCard
            label="High"
            value={stats?.high ?? 0}
            icon={Flame}
            accent={severityColorVar.high}
            hint="Priority triage"
          />
          <StatCard
            label="Medium"
            value={stats?.medium ?? 0}
            icon={AlertTriangle}
            accent={severityColorVar.medium}
            hint="Monitor"
          />
          <StatCard
            label="Low"
            value={stats?.low ?? 0}
            icon={Info}
            accent={severityColorVar.low}
            hint="Informational"
          />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Severity Distribution" description="Incidents grouped by severity">
          {statsQuery.isLoading ? (
            <ChartSkeleton height={240} />
          ) : severityTotal === 0 ? (
            <EmptyState title="No security incidents detected" />
          ) : (
            <div className="space-y-3">
              <ResponsiveContainer width="100%" height={210}>
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={56}
                    outerRadius={84}
                    paddingAngle={2}
                    stroke="var(--background)"
                  >
                    {severityData.map((entry) => (
                      <Cell key={entry.key} fill={severityColorVar[entry.key]} />
                    ))}
                  </Pie>
                  <RechartsTooltip
                    contentStyle={{
                      background: "var(--popover)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      fontSize: 12,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <ul className="grid grid-cols-2 gap-2 text-xs">
                {severityData.map((entry) => (
                  <li key={entry.key} className="flex items-center justify-between gap-2">
                    <span className="flex items-center gap-2 text-muted-foreground">
                      <span
                        className="size-2 rounded-full"
                        style={{ backgroundColor: severityColorVar[entry.key] }}
                      />
                      {entry.name}
                    </span>
                    <span className="font-mono">{entry.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>

        <Panel
          title="Attack Types"
          description="Detections by attack category"
          className="lg:col-span-2"
        >
          {incidentsQuery.isLoading ? (
            <ChartSkeleton height={240} />
          ) : incidentsQuery.isError ? (
            <ErrorState error={incidentsQuery.error} onRetry={() => incidentsQuery.refetch()} />
          ) : attackTypes.length === 0 ? (
            <EmptyState title="No attack events recorded" />
          ) : (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={attackTypes} layout="vertical" margin={{ left: 8, right: 16 }}>
                <XAxis type="number" tick={{ fontSize: 11, fill: "var(--muted-foreground)" }} />
                <YAxis
                  type="category"
                  dataKey="attack"
                  width={150}
                  tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
                />
                <RechartsTooltip
                  cursor={{ fill: "var(--accent)" }}
                  contentStyle={{
                    background: "var(--popover)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" fill="var(--primary)" radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Top Attacker IPs" description="Most active sources">
          {incidentsQuery.isLoading ? (
            <TableSkeleton rows={4} />
          ) : topIps.length === 0 ? (
            <EmptyState title="No attacker IPs detected" icon={<Network className="size-6" />} />
          ) : (
            <ul className="space-y-2">
              {topIps.map((entry) => (
                <li
                  key={entry.ip}
                  className="flex items-center justify-between rounded-md border border-border px-3 py-2"
                >
                  <span className="font-mono text-xs">{entry.ip}</span>
                  <span className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">
                      {entry.count} incident{entry.count === 1 ? "" : "s"}
                    </span>
                    <SeverityBadge
                      severity={
                        entry.severity ??
                        (entry.risk_score !== undefined
                          ? entry.risk_score >= 80
                            ? "critical"
                            : entry.risk_score >= 60
                              ? "high"
                              : entry.risk_score >= 30
                                ? "medium"
                                : "low"
                          : "low")
                      }
                    />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Attack Timeline"
          description="Chronological attack activity"
          className="lg:col-span-2"
        >
          {timelineQuery.isLoading ? (
            <TableSkeleton rows={4} />
          ) : timelineQuery.isError ? (
            <ErrorState error={timelineQuery.error} onRetry={() => timelineQuery.refetch()} />
          ) : (timelineQuery.data?.length ?? 0) === 0 ? (
            <EmptyState title="No attack events recorded" icon={<Activity className="size-6" />} />
          ) : (
            <ol className="relative space-y-4 border-l border-border pl-5">
              {timelineQuery.data!.map((event, index) => (
                <li key={`${event.timestamp}-${index}`} className="relative">
                  <span
                    className="absolute top-1.5 -left-[25px] size-2.5 rounded-full ring-4 ring-card"
                    style={{
                      backgroundColor: severityColorVar[normalizeSeverity(event.severity)],
                    }}
                  />
                  <div className="flex flex-wrap items-center gap-2">
                    <SeverityBadge severity={event.severity} />
                    <span className="text-sm font-medium">{event.attack}</span>
                    <span className="ml-auto text-[11px] text-muted-foreground">
                      {formatTimestamp(event.timestamp)}
                    </span>
                  </div>
                  <div className="mt-1 grid gap-x-6 gap-y-0.5 font-mono text-[11px] text-muted-foreground sm:grid-cols-3">
                    <span>Source: {event.ip}</span>
                    <span>Endpoint: {event.endpoint ?? "—"}</span>
                    <span>MITRE: {event.mitre_technique ?? "—"}</span>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Panel>
      </div>

      <Panel
        title="MITRE ATT&CK Activity"
        description="Techniques observed across incidents"
        action={
          <Link to="/mitre" className="text-xs text-primary hover:underline">
            View all
          </Link>
        }
      >
        {incidentsQuery.isLoading ? (
          <CardSkeletonRow count={4} />
        ) : mitre.length === 0 ? (
          <EmptyState title="No MITRE ATT&CK activity" icon={<Crosshair className="size-6" />} />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {mitre.slice(0, 8).map((item) => (
              <Link
                key={item.technique}
                to="/incidents"
                search={{ technique: item.technique }}
                className="rounded-md border border-border p-3 transition-colors hover:border-primary/50 hover:bg-accent/40"
              >
                <p className="font-mono text-sm text-primary">{item.technique}</p>
                <p className="mt-1 text-sm">{item.technique_name}</p>
                <p className="mt-2 text-[11px] text-muted-foreground">
                  {item.attack ? `${item.attack} · ` : ""}
                  {item.count} incident{item.count === 1 ? "" : "s"}
                </p>
              </Link>
            ))}
          </div>
        )}
      </Panel>

      <Panel
        title="Recent Security Incidents"
        description="Latest detections from the backend"
        action={
          <Link to="/incidents" className="text-xs text-primary hover:underline">
            All incidents
          </Link>
        }
      >
        {incidentsQuery.isLoading ? (
          <TableSkeleton />
        ) : incidentsQuery.isError ? (
          <ErrorState error={incidentsQuery.error} onRetry={() => incidentsQuery.refetch()} />
        ) : (
          <IncidentsTable incidents={incidents} pageSize={5} showControls={false} />
        )}
      </Panel>
    </div>
  );
}
