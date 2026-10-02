import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, Crosshair, Fingerprint, Server } from "lucide-react";
import { Panel, Field } from "@/components/soc/panel";
import { SeverityBadge, severityColorVar } from "@/components/soc/severity-badge";
import { RiskGauge } from "@/components/soc/risk-gauge";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/soc/states";
import { incidentKeys, getIncident } from "@/services/incidents";
import { formatTimestamp } from "@/lib/format";
import { normalizeSeverity } from "@/types/soc";

export const Route = createFileRoute("/_soc/incidents/$id")({
  head: () => ({
    meta: [
      { title: "Incident investigation — SOCVision" },
      {
        name: "description",
        content: "Full incident detail: attack details, MITRE mapping, IOCs and timeline.",
      },
      { property: "og:title", content: "Incident investigation — SOCVision" },
      {
        property: "og:description",
        content: "Full incident detail: attack details, MITRE mapping, IOCs and timeline.",
      },
    ],
  }),
  component: IncidentDetailPage,
});

function IncidentDetailPage() {
  const { id } = Route.useParams();
  const query = useQuery({
    queryKey: incidentKeys.detail(id),
    queryFn: ({ signal }) => getIncident(id, signal),
    retry: false,
  });

  if (query.isLoading) return <TableSkeleton rows={8} />;
  if (query.isError) return <ErrorState error={query.error} onRetry={() => query.refetch()} />;

  const incident = query.data;
  if (!incident) {
    return (
      <div className="space-y-4">
        <BackLink />
        <EmptyState
          title="Incident not found"
          description={`No incident with ID ${id} was returned by the backend.`}
        />
      </div>
    );
  }

  const severity = normalizeSeverity(incident.severity);

  return (
    <div className="space-y-5">
      <BackLink />

      <header className="flex flex-wrap items-center gap-3">
        <h2 className="font-mono text-xl font-semibold tracking-tight">
          Incident #{String(incident.id)}
        </h2>
        <SeverityBadge severity={incident.severity} />
        <span className="text-sm text-muted-foreground">{incident.attack}</span>
        <span className="ml-auto text-xs text-muted-foreground">
          {formatTimestamp(incident.timestamp)}
        </span>
      </header>

      <div className="grid gap-4 lg:grid-cols-3">
        <Panel title="Overview" className="lg:col-span-2">
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="Incident ID" value={<span className="font-mono">{String(incident.id)}</span>} />
            <Field label="Attack Type" value={incident.attack} />
            <Field label="Severity" value={<SeverityBadge severity={incident.severity} />} />
            <Field label="Source IP" value={<span className="font-mono">{incident.ip}</span>} />
            <Field label="Timestamp" value={formatTimestamp(incident.timestamp)} />
            <Field
              label="Status"
              value={
                <span
                  className="rounded border px-2 py-0.5 text-xs"
                  style={{ borderColor: severityColorVar[severity] }}
                >
                  {incident.status ?? "Open"}
                </span>
              }
            />
          </div>
        </Panel>

        <Panel title="Risk Assessment">
          <div className="flex h-full items-center justify-center">
            <RiskGauge score={incident.risk_score ?? 0} />
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Attack Details">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="HTTP Method" value={<span className="font-mono">{incident.method ?? "—"}</span>} />
            <Field label="Endpoint" value={<span className="font-mono">{incident.endpoint ?? "—"}</span>} />
            <Field
              label="HTTP Status"
              value={<span className="font-mono">{incident.status_code ?? "—"}</span>}
            />
            <Field label="Risk Score" value={<span className="font-mono">{incident.risk_score ?? 0}</span>} />
          </div>
        </Panel>

        <Panel title="MITRE ATT&CK">
          {incident.mitre_technique ? (
            <div className="flex items-start gap-3 rounded-md border border-border p-3">
              <Crosshair className="mt-0.5 size-4 text-primary" />
              <div>
                <p className="font-mono text-sm text-primary">{incident.mitre_technique}</p>
                <p className="text-sm">{incident.mitre_technique_name ?? incident.attack}</p>
                <Link
                  to="/incidents"
                  search={{ technique: incident.mitre_technique }}
                  className="mt-2 inline-block text-xs text-primary hover:underline"
                >
                  View related incidents
                </Link>
              </div>
            </div>
          ) : (
            <EmptyState title="No MITRE ATT&CK activity" icon={<Crosshair className="size-6" />} />
          )}
        </Panel>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Indicators of Compromise">
          {incident.iocs?.length ? (
            <ul className="space-y-2">
              {incident.iocs.map((ioc) => (
                <li
                  key={ioc}
                  className="flex items-center gap-2 rounded-md border border-border px-3 py-2 font-mono text-xs break-all"
                >
                  <Fingerprint className="size-3.5 shrink-0 text-muted-foreground" />
                  {ioc}
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState
              title="No indicators of compromise recorded"
              icon={<Fingerprint className="size-6" />}
            />
          )}
        </Panel>

        <Panel title="Timeline">
          <ol className="relative space-y-4 border-l border-border pl-5">
            <li className="relative">
              <span
                className="absolute top-1.5 -left-[25px] size-2.5 rounded-full ring-4 ring-card"
                style={{ backgroundColor: severityColorVar[severity] }}
              />
              <p className="text-sm font-medium">{incident.attack} detected</p>
              <p className="font-mono text-[11px] text-muted-foreground">
                {formatTimestamp(incident.timestamp)} · {incident.ip} → {incident.endpoint ?? "—"}
              </p>
            </li>
            <li className="relative">
              <span className="absolute top-1.5 -left-[25px] size-2.5 rounded-full bg-muted ring-4 ring-card" />
              <p className="flex items-center gap-2 text-sm font-medium">
                <Server className="size-3.5 text-muted-foreground" /> Risk scored{" "}
                {incident.risk_score ?? 0}/100
              </p>
              <p className="text-[11px] text-muted-foreground">
                Classified as {severity} severity by the detection engine.
              </p>
            </li>
          </ol>
        </Panel>
      </div>
    </div>
  );
}

function BackLink() {
  return (
    <Link
      to="/incidents"
      className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="size-3.5" /> Back to incidents
    </Link>
  );
}
