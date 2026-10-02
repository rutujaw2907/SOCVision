import { useMemo } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Crosshair } from "lucide-react";
import { Panel } from "@/components/soc/panel";
import { CardSkeletonRow, EmptyState, ErrorState } from "@/components/soc/states";
import { dashboardKeys, fetchStats } from "@/services/dashboard";
import { incidentKeys, listIncidents } from "@/services/incidents";
import { deriveMitre } from "./_soc.dashboard";

export const Route = createFileRoute("/_soc/mitre")({
  head: () => ({
    meta: [
      { title: "MITRE ATT&CK — SOCVision" },
      {
        name: "description",
        content: "Adversary techniques observed across SOCVision incidents, mapped to MITRE ATT&CK.",
      },
      { property: "og:title", content: "MITRE ATT&CK — SOCVision" },
      {
        property: "og:description",
        content: "Adversary techniques observed across SOCVision incidents, mapped to MITRE ATT&CK.",
      },
    ],
  }),
  component: MitrePage,
});

function MitrePage() {
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

  const techniques = useMemo(
    () => deriveMitre(statsQuery.data, incidentsQuery.data ?? []),
    [statsQuery.data, incidentsQuery.data],
  );

  return (
    <div className="space-y-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">MITRE ATT&CK Activity</h2>
        <p className="text-sm text-muted-foreground">
          Adversary techniques observed across detected incidents
        </p>
      </header>

      <Panel>
        {incidentsQuery.isLoading ? (
          <CardSkeletonRow count={4} />
        ) : incidentsQuery.isError ? (
          <ErrorState error={incidentsQuery.error} onRetry={() => incidentsQuery.refetch()} />
        ) : techniques.length === 0 ? (
          <EmptyState title="No MITRE ATT&CK activity" icon={<Crosshair className="size-6" />} />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {techniques.map((item) => (
              <Link
                key={item.technique}
                to="/incidents"
                search={{ technique: item.technique }}
                className="rounded-md border border-border p-4 transition-colors hover:border-primary/50 hover:bg-accent/40"
              >
                <div className="flex items-center justify-between">
                  <p className="font-mono text-sm text-primary">{item.technique}</p>
                  <span className="font-mono text-xs text-muted-foreground">
                    {item.count} incident{item.count === 1 ? "" : "s"}
                  </span>
                </div>
                <p className="mt-1 text-sm">{item.technique_name}</p>
                {item.attack ? (
                  <p className="mt-2 text-[11px] text-muted-foreground">
                    Associated attack: {item.attack}
                  </p>
                ) : null}
              </Link>
            ))}
          </div>
        )}
      </Panel>
    </div>
  );
}
