import { useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, FileText, Loader2, Upload, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Panel, Field } from "@/components/soc/panel";
import { SeverityBadge } from "@/components/soc/severity-badge";
import { RiskGauge, RiskBar } from "@/components/soc/risk-gauge";
import { EmptyState, ErrorState } from "@/components/soc/states";
import { analyzeLog } from "@/services/analyzer";
import { formatBytes } from "@/lib/format";
import { severityFromScore, type AnalyzerResult } from "@/types/soc";

export const Route = createFileRoute("/_soc/analyzer")({
  head: () => ({
    meta: [
      { title: "Log Analyzer — SOCVision" },
      {
        name: "description",
        content: "Upload security logs for automated threat detection and risk analysis.",
      },
      { property: "og:title", content: "Log Analyzer — SOCVision" },
      {
        property: "og:description",
        content: "Upload security logs for automated threat detection and risk analysis.",
      },
    ],
  }),
  component: AnalyzerPage,
});

const ACCEPTED = [".log", ".txt"];

function AnalyzerPage() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [result, setResult] = useState<AnalyzerResult | null>(null);

  const mutation = useMutation({
    mutationFn: (selected: File) => analyzeLog(selected),
    onSuccess: (data) => setResult(data),
  });

  const pick = (selected: File | undefined) => {
    if (!selected) return;
    const ok = ACCEPTED.some((ext) => selected.name.toLowerCase().endsWith(ext));
    if (!ok) return;
    setResult(null);
    mutation.reset();
    setFile(selected);
  };

  const threats = result?.threats ?? [];
  const riskScore = result?.risk_score ?? 0;

  return (
    <div className="space-y-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Log Analyzer</h2>
        <p className="text-sm text-muted-foreground">
          Upload security logs for automated threat detection and risk analysis.
        </p>
      </header>

      <Panel title="Upload log file" description="Accepted formats: .log, .txt">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            pick(e.dataTransfer.files?.[0]);
          }}
          className={`flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-6 py-12 text-center transition-colors ${
            dragging ? "border-primary bg-primary/5" : "border-border"
          }`}
        >
          <Upload className="size-7 text-muted-foreground" />
          <div>
            <p className="text-sm font-medium">Drag and drop a log file here</p>
            <p className="text-xs text-muted-foreground">or browse from your machine</p>
          </div>
          <input
            ref={inputRef}
            type="file"
            accept=".log,.txt"
            className="sr-only"
            onChange={(e) => pick(e.target.files?.[0])}
          />
          <Button variant="outline" size="sm" onClick={() => inputRef.current?.click()}>
            Select file
          </Button>
        </div>

        {file ? (
          <div className="mt-4 flex flex-wrap items-center gap-3 rounded-md border border-border px-3 py-2">
            <FileText className="size-4 text-primary" />
            <span className="text-sm">{file.name}</span>
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
          <Button disabled={!file || mutation.isPending} onClick={() => file && mutation.mutate(file)}>
            {mutation.isPending ? (
              <>
                <Loader2 className="size-4 animate-spin" /> Analyzing log…
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
            onRetry={() => file && mutation.mutate(file)}
          />
        ) : null}
      </Panel>

      {mutation.isPending ? (
        <Panel>
          <div className="flex flex-col items-center gap-3 py-10 text-center">
            <Loader2 className="size-6 animate-spin text-primary" />
            <p className="text-sm">Scanning log entries for threat indicators…</p>
          </div>
        </Panel>
      ) : null}

      {result ? (
        <>
          <Panel
            title="Analysis Summary"
            action={
              <span className="flex items-center gap-1.5 text-xs text-online">
                <CheckCircle2 className="size-3.5" /> Analysis complete
              </span>
            }
          >
            <div className="grid items-center gap-5 md:grid-cols-[1fr_auto]">
              <div className="grid gap-4 sm:grid-cols-3">
                <Field label="File" value={result.file ?? result.filename ?? file?.name ?? "—"} />
                <Field label="Log Type" value={result.log_type ?? "—"} />
                <Field
                  label="Total Logs"
                  value={<span className="font-mono">{result.total_logs ?? 0}</span>}
                />
                <Field
                  label="Threats Found"
                  value={<span className="font-mono">{result.threats_found ?? threats.length}</span>}
                />
                <Field
                  label="Risk Severity"
                  value={
                    <SeverityBadge severity={result.risk_severity ?? severityFromScore(riskScore)} />
                  }
                />
                <Field label="Risk Score" value={<RiskBar score={riskScore} />} />
              </div>
              <RiskGauge score={riskScore} />
            </div>
          </Panel>

          <Panel title="Detected Threats">
            {threats.length === 0 ? (
              <EmptyState
                title="No threats detected in this log"
                description="The analyzer did not flag any suspicious activity."
              />
            ) : (
              <div className="grid gap-3 md:grid-cols-2">
                {threats.map((threat, index) => (
                  <article key={index} className="rounded-md border border-border p-4">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-medium">{threat.attack}</p>
                      <SeverityBadge severity={threat.severity} />
                    </div>
                    <div className="mt-3 grid gap-3 sm:grid-cols-2">
                      <Field label="Risk Score" value={<RiskBar score={threat.risk_score} />} />
                      <Field
                        label="MITRE Technique"
                        value={<span className="font-mono">{threat.mitre_technique ?? "—"}</span>}
                      />
                      <Field
                        label="Source IP"
                        value={<span className="font-mono">{threat.ip ?? "—"}</span>}
                      />
                      <Field label="Reason" value={threat.reason ?? "—"} />
                    </div>
                  </article>
                ))}
              </div>
            )}
          </Panel>
        </>
      ) : null}
    </div>
  );
}
