import { createFileRoute, Link } from "@tanstack/react-router";
import {
  useMutation,
  useQuery,
} from "@tanstack/react-query";
import {
  ArrowLeft,
  BrainCircuit,
  Crosshair,
  FileDown,
  Fingerprint,
  Server,
} from "lucide-react";

import { Panel, Field } from "@/components/soc/panel";
import {
  SeverityBadge,
  severityColorVar,
} from "@/components/soc/severity-badge";
import { RiskGauge } from "@/components/soc/risk-gauge";
import {
  EmptyState,
  ErrorState,
  TableSkeleton,
} from "@/components/soc/states";

import {
  incidentKeys,
  getIncident,
  updateIncidentStatus,
  downloadIncidentReport,
} from "@/services/incidents";

import { analyzeIncidentWithAI } from "@/services/aiAnalyst";

import { formatTimestamp } from "@/lib/format";
import { normalizeSeverity } from "@/types/soc";


export const Route = createFileRoute(
  "/_soc/incidents/$id"
)({
  head: () => ({
    meta: [
      {
        title:
          "Incident investigation — SOCVision",
      },
      {
        name: "description",
        content:
          "Full incident detail: attack details, MITRE mapping, IOCs, AI analysis and timeline.",
      },
      {
        property: "og:title",
        content:
          "Incident investigation — SOCVision",
      },
      {
        property: "og:description",
        content:
          "Full incident detail with AI-powered security analysis.",
      },
    ],
  }),

  component: IncidentDetailPage,
});


type IncidentStatus =
  | "OPEN"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED";


const INCIDENT_STATUSES: IncidentStatus[] = [
  "OPEN",
  "INVESTIGATING",
  "CONTAINED",
  "RESOLVED",
];


function IncidentDetailPage() {

  const { id } =
    Route.useParams();


  const query = useQuery({
    queryKey:
      incidentKeys.detail(id),

    queryFn: ({
      signal,
    }) =>
      getIncident(
        id,
        signal,
      ),

    retry: false,
  });


  const statusMutation =
    useMutation({

      mutationFn: (
        status: IncidentStatus
      ) =>
        updateIncidentStatus(
          id,
          status,
        ),

      onSuccess: () => {
        query.refetch();
      },

    });


  const aiMutation =
    useMutation({

      mutationFn: ({
        signal,
      }: {
        signal?: AbortSignal;
      }) =>
        analyzeIncidentWithAI(
          id,
          signal,
        ),

    });


  const reportMutation =
    useMutation({

      mutationFn: () =>
        downloadIncidentReport(
          id,
        ),

    });


  if (query.isLoading) {

    return (
      <TableSkeleton
        rows={8}
      />
    );

  }


  if (query.isError) {

    return (
      <ErrorState
        error={
          query.error
        }
        onRetry={() =>
          query.refetch()
        }
      />
    );

  }


  const incident =
    query.data;


  if (!incident) {

    return (
      <div className="space-y-4">

        <BackLink />

        <EmptyState
          title="Incident not found"
          description={
            `No incident with ID ${id} was returned by the backend.`
          }
        />

      </div>
    );

  }


  const severity =
    normalizeSeverity(
      incident.severity,
    );


  const currentStatus = (
    (
      incident.incident_status ??
      "OPEN"
    ).toUpperCase()
  ) as IncidentStatus;


  return (
    <div className="space-y-5">

      <BackLink />


      {/* Header */}
      <header className="flex flex-wrap items-center gap-3">

        <h2 className="font-mono text-xl font-semibold tracking-tight">
          Incident #{String(
            incident.id,
          )}
        </h2>


        <SeverityBadge
          severity={
            incident.severity
          }
        />


        <span className="text-sm text-muted-foreground">
          {incident.attack}
        </span>


        <span className="ml-auto text-xs text-muted-foreground">
          {formatTimestamp(
            incident.timestamp,
          )}
        </span>


        <button
          type="button"
          disabled={
            reportMutation.isPending
          }
          onClick={() =>
            reportMutation.mutate()
          }
          className={[
            "inline-flex items-center gap-2 rounded-md border px-3 py-2 text-xs font-medium transition",
            "border-border bg-card text-foreground",
            "hover:bg-muted",
            reportMutation.isPending
              ? "cursor-not-allowed opacity-50"
              : "",
          ].join(" ")}
        >

          <FileDown className="size-3.5" />

          {reportMutation.isPending
            ? "Generating..."
            : "Download PDF"}

        </button>

      </header>


      {/* PDF error */}
      {reportMutation.isError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3">

          <p className="text-xs text-destructive">
            Failed to generate the PDF report.
          </p>

          <p className="mt-1 text-xs text-muted-foreground">
            {reportMutation.error instanceof Error
              ? reportMutation.error.message
              : "Please try again."}
          </p>

        </div>
      )}


      {/* Incident Workflow */}
      <Panel title="Incident Status">

        <div className="space-y-4">

          <div className="flex flex-wrap gap-2">

            {INCIDENT_STATUSES.map(
              (status) => {

                const isActive =
                  currentStatus ===
                  status;


                return (
                  <button
                    key={status}
                    type="button"
                    disabled={
                      statusMutation.isPending
                    }
                    onClick={() =>
                      statusMutation.mutate(
                        status,
                      )
                    }
                    className={[
                      "rounded-md border px-3 py-2 text-xs font-medium transition",
                      isActive
                        ? "border-primary bg-primary text-primary-foreground"
                        : "border-border bg-card text-muted-foreground hover:bg-muted hover:text-foreground",
                      statusMutation.isPending
                        ? "cursor-not-allowed opacity-50"
                        : "",
                    ].join(" ")}
                  >
                    {status}
                  </button>
                );

              },
            )}

          </div>


          <div className="flex items-center gap-2 text-xs text-muted-foreground">

            <span>
              Current status:
            </span>

            <span className="font-semibold text-foreground">
              {currentStatus}
            </span>


            {incident.updated_at && (
              <>
                <span>
                  •
                </span>

                <span>
                  Updated{" "}
                  {formatTimestamp(
                    incident.updated_at,
                  )}
                </span>
              </>
            )}

          </div>


          {statusMutation.isError && (
            <p className="text-xs text-destructive">
              Failed to update incident status.
              Please try again.
            </p>
          )}

        </div>

      </Panel>


      {/* AI Security Analyst */}
      <Panel title="AI Security Analyst">

        <div className="space-y-4">

          <div className="flex flex-wrap items-center gap-3">

            <div className="flex items-center gap-2">

              <div className="flex size-9 items-center justify-center rounded-md border border-border bg-muted">

                <BrainCircuit className="size-5 text-primary" />

              </div>


              <div>

                <p className="text-sm font-medium">
                  Automated Incident Analysis
                </p>

                <p className="text-xs text-muted-foreground">
                  Analyze this incident using the supplied SOCVision evidence.
                </p>

              </div>

            </div>


            <button
              type="button"
              disabled={
                aiMutation.isPending
              }
              onClick={() =>
                aiMutation.mutate({})
              }
              className={[
                "ml-auto rounded-md border px-4 py-2 text-xs font-medium transition",
                "border-primary bg-primary text-primary-foreground",
                aiMutation.isPending
                  ? "cursor-not-allowed opacity-50"
                  : "hover:opacity-90",
              ].join(" ")}
            >
              {aiMutation.isPending
                ? "Analyzing..."
                : "Analyze Incident"}
            </button>

          </div>


          {aiMutation.isError && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3">

              <p className="text-xs font-medium text-destructive">
                AI analysis failed.
              </p>

              <p className="mt-1 text-xs text-muted-foreground">
                {aiMutation.error instanceof Error
                  ? aiMutation.error.message
                  : "The AI Security Analyst is currently unavailable."}
              </p>

            </div>
          )}


          {aiMutation.data?.analysis && (
            <div className="rounded-md border border-border bg-card">

              <div className="flex items-center justify-between border-b border-border px-4 py-3">

                <div>

                  <p className="text-sm font-semibold">
                    Analyst Report
                  </p>

                  {aiMutation.data.model && (
                    <p className="font-mono text-[10px] text-muted-foreground">
                      Model:{" "}
                      {aiMutation.data.model}
                    </p>
                  )}

                </div>


                <span className="rounded border border-border px-2 py-1 text-[10px] text-muted-foreground">
                  AI GENERATED
                </span>

              </div>


              <div className="whitespace-pre-wrap px-4 py-4 text-sm leading-6 text-muted-foreground">
                {aiMutation.data.analysis}
              </div>

            </div>
          )}


          {!aiMutation.data &&
            !aiMutation.isPending &&
            !aiMutation.isError && (

              <div className="rounded-md border border-dashed border-border p-6 text-center">

                <BrainCircuit className="mx-auto size-6 text-muted-foreground" />

                <p className="mt-2 text-sm font-medium">
                  No AI analysis generated yet
                </p>

                <p className="mt-1 text-xs text-muted-foreground">
                  Click “Analyze Incident” to generate an analyst-oriented investigation report.
                </p>

              </div>

            )}

        </div>

      </Panel>


      {/* Overview + Risk */}
      <div className="grid gap-4 lg:grid-cols-3">

        <Panel
          title="Overview"
          className="lg:col-span-2"
        >

          <div className="grid gap-4 sm:grid-cols-3">

            <Field
              label="Incident ID"
              value={
                <span className="font-mono">
                  {String(
                    incident.id,
                  )}
                </span>
              }
            />


            <Field
              label="Attack Type"
              value={
                incident.attack
              }
            />


            <Field
              label="Severity"
              value={
                <SeverityBadge
                  severity={
                    incident.severity
                  }
                />
              }
            />


            <Field
              label="Source IP"
              value={
                <span className="font-mono">
                  {incident.ip}
                </span>
              }
            />


            <Field
              label="Timestamp"
              value={
                formatTimestamp(
                  incident.timestamp,
                )
              }
            />


            <Field
              label="Workflow Status"
              value={
                <span className="rounded border border-border px-2 py-0.5 text-xs">
                  {currentStatus}
                </span>
              }
            />

          </div>

        </Panel>


        <Panel title="Risk Assessment">

          <div className="flex h-full items-center justify-center">

            <RiskGauge
              score={
                incident.risk_score ??
                0
              }
            />

          </div>

        </Panel>

      </div>


      {/* Attack Details + MITRE */}
      <div className="grid gap-4 lg:grid-cols-2">

        <Panel title="Attack Details">

          <div className="grid gap-4 sm:grid-cols-2">

            <Field
              label="HTTP Method"
              value={
                <span className="font-mono">
                  {incident.method ??
                    "—"}
                </span>
              }
            />


            <Field
              label="Endpoint"
              value={
                <span className="font-mono">
                  {incident.endpoint ??
                    "—"}
                </span>
              }
            />


            <Field
              label="HTTP Status"
              value={
                <span className="font-mono">
                  {incident.status_code ??
                    "—"}
                </span>
              }
            />


            <Field
              label="Risk Score"
              value={
                <span className="font-mono">
                  {incident.risk_score ??
                    0}
                </span>
              }
            />

          </div>

        </Panel>


        <Panel title="MITRE ATT&CK">

          {incident.mitre_technique ? (

            <div className="flex items-start gap-3 rounded-md border border-border p-3">

              <Crosshair className="mt-0.5 size-4 text-primary" />


              <div>

                <p className="font-mono text-sm text-primary">
                  {incident.mitre_technique}
                </p>


                <p className="text-sm">
                  {
                    incident.mitre_technique_name ??
                    incident.attack
                  }
                </p>


                <Link
                  to="/incidents"
                  search={{
                    technique:
                      incident.mitre_technique,
                  }}
                  className="mt-2 inline-block text-xs text-primary hover:underline"
                >
                  View related incidents
                </Link>

              </div>

            </div>

          ) : (

            <EmptyState
              title="No MITRE ATT&CK activity"
              icon={
                <Crosshair className="size-6" />
              }
            />

          )}

        </Panel>

      </div>


      {/* IOCs + Timeline */}
      <div className="grid gap-4 lg:grid-cols-2">

        <Panel title="Indicators of Compromise">

          {incident.iocs?.length ? (

            <ul className="space-y-2">

              {incident.iocs.map(
                (ioc) => (

                  <li
                    key={ioc}
                    className="flex items-center gap-2 rounded-md border border-border px-3 py-2 font-mono text-xs break-all"
                  >

                    <Fingerprint className="size-3.5 shrink-0 text-muted-foreground" />

                    {ioc}

                  </li>

                ),
              )}

            </ul>

          ) : (

            <EmptyState
              title="No indicators of compromise recorded"
              icon={
                <Fingerprint className="size-6" />
              }
            />

          )}

        </Panel>


        <Panel title="Timeline">

          <ol className="relative space-y-4 border-l border-border pl-5">

            <li className="relative">

              <span
                className="absolute top-1.5 -left-[25px] size-2.5 rounded-full ring-4 ring-card"
                style={{
                  backgroundColor:
                    severityColorVar[
                      severity
                    ],
                }}
              />


              <p className="text-sm font-medium">
                {incident.attack} detected
              </p>


              <p className="font-mono text-[11px] text-muted-foreground">
                {formatTimestamp(
                  incident.timestamp,
                )}{" "}
                ·{" "}
                {incident.ip}{" "}
                →{" "}
                {incident.endpoint ??
                  "—"}
              </p>

            </li>


            <li className="relative">

              <span className="absolute top-1.5 -left-[25px] size-2.5 rounded-full bg-muted ring-4 ring-card" />


              <p className="flex items-center gap-2 text-sm font-medium">

                <Server className="size-3.5 text-muted-foreground" />

                Risk scored{" "}
                {incident.risk_score ??
                  0}
                /100

              </p>


              <p className="text-[11px] text-muted-foreground">
                Classified as{" "}
                {severity}{" "}
                severity by the detection engine.
              </p>

            </li>


            <li className="relative">

              <span className="absolute top-1.5 -left-[25px] size-2.5 rounded-full bg-primary ring-4 ring-card" />


              <p className="text-sm font-medium">
                Incident status:{" "}
                {currentStatus}
              </p>


              <p className="text-[11px] text-muted-foreground">
                Current SOC investigation state.
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
      <ArrowLeft className="size-3.5" />

      Back to incidents
    </Link>
  );

}