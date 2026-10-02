import { useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import {
  CheckCircle2,
  FileText,
  Loader2,
  Upload,
  X,
  ShieldCheck,
  ShieldAlert,
  Activity,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Panel, Field } from "@/components/soc/panel";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { RiskGauge, RiskBar } from "@/components/soc/risk-gauge";
import { EmptyState, ErrorState } from "@/components/soc/states";
import { analyzeLog } from "@/services/analyzer";
import { formatBytes } from "@/lib/format";
import {
  severityFromScore,
  type AnalyzerResult,
} from "@/types/soc";

export const Route = createFileRoute("/_soc/analyzer")({
  head: () => ({
    meta: [
      { title: "Log Analyzer — SOCVision" },
      {
        name: "description",
        content:
          "Upload security logs for automated threat detection and risk analysis.",
      },
      {
        property: "og:title",
        content: "Log Analyzer — SOCVision",
      },
      {
        property: "og:description",
        content:
          "Upload security logs for automated threat detection and risk analysis.",
      },
    ],
  }),
  component: AnalyzerPage,
});

const ACCEPTED = [".log", ".txt"];

type VirusTotalResult = {
  available?: boolean;
  ip?: string;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reputation?: number;
  error?: string;
};

type AbuseIPDBResult = {
  available?: boolean;
  ip?: string;
  abuse_confidence_score?: number;
  total_reports?: number;
  country_code?: string | null;
  country_name?: string | null;
  isp?: string | null;
  domain?: string | null;
  usage_type?: string | null;
  is_whitelisted?: boolean | null;
  last_reported_at?: string | null;
  error?: string;
};

type ThreatIntelligenceResult = {
  ip?: string | null;
  virustotal?: VirusTotalResult | null;
  abuseipdb?: AbuseIPDBResult | null;
};

type AnalyzerResultWithIntel = AnalyzerResult & {
  threat_intelligence?: ThreatIntelligenceResult[];
};

function AnalyzerPage() {
  const inputRef = useRef<HTMLInputElement>(null);

  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [result, setResult] =
    useState<AnalyzerResult | null>(null);

  const mutation = useMutation({
    mutationFn: (selected: File) =>
      analyzeLog(selected),

    onSuccess: (data) =>
      setResult(data),
  });

  const pick = (
    selected: File | undefined
  ) => {
    if (!selected) return;

    const ok = ACCEPTED.some(
      (ext) =>
        selected.name
          .toLowerCase()
          .endsWith(ext)
    );

    if (!ok) return;

    setResult(null);
    mutation.reset();
    setFile(selected);
  };

  const threats =
    result?.threats ?? [];

  const riskScore =
    result?.risk_score ?? 0;

  const resultWithIntel =
    result as AnalyzerResultWithIntel | null;

  const threatIntelligence =
    resultWithIntel?.threat_intelligence ?? [];

  return (
    <div className="space-y-5">

      {/* PAGE HEADER */}
      <header>
        <h2 className="text-xl font-semibold tracking-tight">
          Log Analyzer
        </h2>

        <p className="text-sm text-muted-foreground">
          Upload security logs for automated threat detection
          and risk analysis.
        </p>
      </header>

      {/* UPLOAD */}
      <Panel
        title="Upload log file"
        description="Accepted formats: .log, .txt"
      >
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() =>
            setDragging(false)
          }
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);

            pick(
              e.dataTransfer.files?.[0]
            );
          }}
          className={`flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-6 py-12 text-center transition-colors ${
            dragging
              ? "border-primary bg-primary/5"
              : "border-border"
          }`}
        >
          <Upload className="size-7 text-muted-foreground" />

          <div>
            <p className="text-sm font-medium">
              Drag and drop a log file here
            </p>

            <p className="text-xs text-muted-foreground">
              or browse from your machine
            </p>
          </div>

          <input
            ref={inputRef}
            type="file"
            accept=".log,.txt"
            className="sr-only"
            onChange={(e) =>
              pick(e.target.files?.[0])
            }
          />

          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              inputRef.current?.click()
            }
          >
            Select file
          </Button>
        </div>

        {file ? (
          <div className="mt-4 flex flex-wrap items-center gap-3 rounded-md border border-border px-3 py-2">
            <FileText className="size-4 text-primary" />

            <span className="text-sm">
              {file.name}
            </span>

            <span className="font-mono text-xs text-muted-foreground">
              {formatBytes(file.size)}
            </span>

            <Button
              variant="ghost"
              size="icon"
              aria-label="Remove file"
              className="ml-auto"
              onClick={() => {
                setFile(null);
                setResult(null);
                mutation.reset();
              }}
            >
              <X className="size-4" />
            </Button>
          </div>
        ) : null}

        <div className="mt-4">
          <Button
            disabled={
              !file ||
              mutation.isPending
            }
            onClick={() =>
              file &&
              mutation.mutate(file)
            }
          >
            {mutation.isPending ? (
              <>
                <Loader2 className="size-4 animate-spin" />
                Analyzing log…
              </>
            ) : (
              "Analyze Log"
            )}
          </Button>
        </div>

        {mutation.isError ? (
          <ErrorState
            className="mt-4"
            error={mutation.error}
            onRetry={() =>
              file &&
              mutation.mutate(file)
            }
          />
        ) : null}
      </Panel>

      {/* LOADING */}
      {mutation.isPending ? (
        <Panel>
          <div className="flex flex-col items-center gap-3 py-10 text-center">
            <Loader2 className="size-6 animate-spin text-primary" />

            <p className="text-sm">
              Scanning log entries for threat indicators…
            </p>
          </div>
        </Panel>
      ) : null}

      {result ? (
        <>
          {/* ANALYSIS SUMMARY */}
          <Panel
            title="Analysis Summary"
            action={
              <span className="flex items-center gap-1.5 text-xs text-online">
                <CheckCircle2 className="size-3.5" />
                Analysis complete
              </span>
            }
          >
            <div className="grid items-center gap-5 md:grid-cols-[1fr_auto]">

              <div className="grid gap-4 sm:grid-cols-3">

                <Field
                  label="File"
                  value={
                    result.file ??
                    result.filename ??
                    file?.name ??
                    "—"
                  }
                />

                <Field
                  label="Log Type"
                  value={
                    result.log_type ?? "—"
                  }
                />

                <Field
                  label="Total Logs"
                  value={
                    <span className="font-mono">
                      {result.total_logs ?? 0}
                    </span>
                  }
                />

                <Field
                  label="Threats Found"
                  value={
                    <span className="font-mono">
                      {result.threats_found ??
                        threats.length}
                    </span>
                  }
                />

                <Field
                  label="Risk Severity"
                  value={
                    <SeverityBadge
                      severity={
                        result.risk_severity ??
                        severityFromScore(
                          riskScore
                        )
                      }
                    />
                  }
                />

                <Field
                  label="Risk Score"
                  value={
                    <RiskBar
                      score={riskScore}
                    />
                  }
                />
              </div>

              <RiskGauge
                score={riskScore}
              />
            </div>
          </Panel>

          {/* DETECTED THREATS */}
          <Panel title="Detected Threats">

            {threats.length === 0 ? (
              <EmptyState
                title="No threats detected in this log"
                description="The analyzer did not flag any suspicious activity."
              />
            ) : (
              <div className="grid gap-3 md:grid-cols-2">

                {threats.map(
                  (threat, index) => (
                    <article
                      key={index}
                      className="rounded-md border border-border p-4"
                    >
                      <div className="flex items-center justify-between gap-2">

                        <p className="text-sm font-medium">
                          {threat.attack}
                        </p>

                        <SeverityBadge
                          severity={
                            threat.severity
                          }
                        />
                      </div>

                      <div className="mt-3 grid gap-3 sm:grid-cols-2">

                        <Field
                          label="Risk Score"
                          value={
                            <RiskBar
                              score={
                                threat.risk_score
                              }
                            />
                          }
                        />

                        <Field
                          label="MITRE Technique"
                          value={
                            <span className="font-mono">
                              {threat.mitre_technique ??
                                "—"}
                            </span>
                          }
                        />

                        <Field
                          label="Source IP"
                          value={
                            <span className="font-mono">
                              {threat.ip ?? "—"}
                            </span>
                          }
                        />

                        <Field
                          label="Reason"
                          value={
                            threat.reason ?? "—"
                          }
                        />
                      </div>
                    </article>
                  )
                )}
              </div>
            )}
          </Panel>

          {/* THREAT INTELLIGENCE */}
          {threatIntelligence.length > 0 ? (
            <Panel
              title="Threat Intelligence"
              description="External intelligence enrichment for detected source IPs."
            >
              <div className="space-y-5">

                {threatIntelligence.map(
                  (intel, index) => {

                    const vt =
                      intel.virustotal;

                    const abuse =
                      intel.abuseipdb;

                    const vtMalicious =
                      vt?.malicious ?? 0;

                    const vtSuspicious =
                      vt?.suspicious ?? 0;

                    const vtReputation =
                      vt?.reputation ?? 0;

                    const abuseScore =
                      abuse?.abuse_confidence_score ??
                      0;

                    const vtAvailable =
                      vt?.available === true;

                    const abuseAvailable =
                      abuse?.available === true;

                    return (
                      <article
                        key={`${intel.ip}-${index}`}
                        className="rounded-lg border border-border bg-background/30 p-5"
                      >

                        {/* IP HEADER */}
                        <div className="flex flex-wrap items-start justify-between gap-4">

                          <div className="flex items-center gap-3">

                            <div className="flex size-10 items-center justify-center rounded-md border border-border bg-muted/30">
                              {vtAvailable ||
                              abuseAvailable ? (
                                <ShieldCheck className="size-5 text-online" />
                              ) : (
                                <ShieldAlert className="size-5 text-muted-foreground" />
                              )}
                            </div>

                            <div>
                              <p className="text-xs uppercase tracking-wider text-muted-foreground">
                                Source IP
                              </p>

                              <p className="font-mono text-sm font-semibold">
                                {intel.ip ??
                                  "Unknown"}
                              </p>
                            </div>
                          </div>

                          <div className="flex gap-2">

                            <span
                              className={`rounded-md border px-2 py-1 text-xs ${
                                vtAvailable
                                  ? "border-online/30 bg-online/10 text-online"
                                  : "border-border text-muted-foreground"
                              }`}
                            >
                              VirusTotal
                            </span>

                            <span
                              className={`rounded-md border px-2 py-1 text-xs ${
                                abuseAvailable
                                  ? "border-online/30 bg-online/10 text-online"
                                  : "border-border text-muted-foreground"
                              }`}
                            >
                              AbuseIPDB
                            </span>

                          </div>
                        </div>

                        {/* PROVIDER CARDS */}
                        <div className="mt-5 grid gap-4 lg:grid-cols-2">

                          {/* VIRUSTOTAL */}
                          <div className="rounded-md border border-border p-4">

                            <div className="flex items-center gap-2">

                              <Activity className="size-4 text-primary" />

                              <h3 className="text-sm font-semibold">
                                VirusTotal
                              </h3>

                            </div>

                            {vtAvailable ? (
                              <div className="mt-4 grid grid-cols-2 gap-3">

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Malicious
                                  </p>

                                  <p className="mt-1 font-mono text-lg font-semibold">
                                    {vtMalicious}
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Suspicious
                                  </p>

                                  <p className="mt-1 font-mono text-lg font-semibold">
                                    {vtSuspicious}
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Harmless
                                  </p>

                                  <p className="mt-1 font-mono text-lg font-semibold">
                                    {vt?.harmless ?? 0}
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Reputation
                                  </p>

                                  <p className="mt-1 font-mono text-lg font-semibold">
                                    {vtReputation}
                                  </p>
                                </div>

                              </div>
                            ) : (
                              <div className="mt-4 rounded-md border border-border p-3 text-sm text-muted-foreground">
                                VirusTotal unavailable.
                                {vt?.error
                                  ? ` ${vt.error}`
                                  : ""}
                              </div>
                            )}
                          </div>

                          {/* ABUSEIPDB */}
                          <div className="rounded-md border border-border p-4">

                            <div className="flex items-center gap-2">

                              <ShieldAlert className="size-4 text-primary" />

                              <h3 className="text-sm font-semibold">
                                AbuseIPDB
                              </h3>

                            </div>

                            {abuseAvailable ? (
                              <div className="mt-4 grid grid-cols-2 gap-3">

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Abuse Confidence
                                  </p>

                                  <p className="mt-1 font-mono text-lg font-semibold">
                                    {abuseScore}%
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Reports
                                  </p>

                                  <p className="mt-1 font-mono text-lg font-semibold">
                                    {abuse?.total_reports ?? 0}
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Country
                                  </p>

                                  <p className="mt-1 font-mono text-sm font-semibold">
                                    {abuse?.country_code ??
                                      "—"}
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    ISP
                                  </p>

                                  <p className="mt-1 truncate text-sm font-semibold">
                                    {abuse?.isp ??
                                      "—"}
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Usage Type
                                  </p>

                                  <p className="mt-1 text-sm font-semibold">
                                    {abuse?.usage_type ??
                                      "—"}
                                  </p>
                                </div>

                                <div className="rounded-md border border-border p-3">
                                  <p className="text-xs text-muted-foreground">
                                    Whitelisted
                                  </p>

                                  <p className="mt-1 text-sm font-semibold">
                                    {abuse?.is_whitelisted === true
                                      ? "Yes"
                                      : "No"}
                                  </p>
                                </div>

                              </div>
                            ) : (
                              <div className="mt-4 rounded-md border border-border p-3 text-sm text-muted-foreground">
                                AbuseIPDB unavailable.
                                {abuse?.error
                                  ? ` ${abuse.error}`
                                  : ""}
                              </div>
                            )}
                          </div>

                        </div>
                      </article>
                    );
                  }
                )}
              </div>
            </Panel>
          ) : null}
        </>
      ) : null}
    </div>
  );
}