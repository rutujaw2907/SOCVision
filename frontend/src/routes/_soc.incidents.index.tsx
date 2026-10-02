import { useMemo } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Panel } from "@/components/soc/panel";
import { IncidentsTable } from "@/components/soc/incidents-table";
import { ErrorState, TableSkeleton } from "@/components/soc/states";
import { incidentKeys, listIncidents } from "@/services/incidents";

export const Route = createFileRoute("/_soc/incidents/")({
  validateSearch: (search: Record<string, unknown>) => ({
    technique: typeof search.technique === "string" ? search.technique : undefined,
  }),
  head: () => ({
    meta: [
      { title: "Incidents — SOCVision" },
      {
        name: "description",
        content: "Search, filter and triage detected security incidents by severity and risk.",
      },
      { property: "og:title", content: "Incidents — SOCVision" },
      {
        property: "og:description",
        content: "Search, filter and triage detected security incidents by severity and risk.",
      },
    ],
  }),
  component: IncidentsPage,
});

function IncidentsPage() {
  const { technique } = Route.useSearch();
  const query = useQuery({
    queryKey: incidentKeys.list,
    queryFn: ({ signal }) => listIncidents(signal),
    retry: false,
  });

  const incidents = useMemo(() => {
    const rows = query.data ?? [];
    return technique ? rows.filter((row) => row.mitre_technique === technique) : rows;
  }, [query.data, technique]);

  return (
    <div className="space-y-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Security Incidents</h2>
        <p className="text-sm text-muted-foreground">
          {technique
            ? `Incidents mapped to MITRE technique ${technique}`
            : "Investigate and triage detections reported by the SOCVision backend"}
        </p>
      </header>

      <Panel>
        {query.isLoading ? (
          <TableSkeleton rows={8} />
        ) : query.isError ? (
          <ErrorState error={query.error} onRetry={() => query.refetch()} />
        ) : (
          <IncidentsTable incidents={incidents} pageSize={12} />
        )}
      </Panel>
    </div>
  );
}
