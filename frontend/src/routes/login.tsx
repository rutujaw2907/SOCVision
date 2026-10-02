import { useEffect, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { AlertTriangle, Eye, EyeOff, Loader2, Lock, Shield } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { login } from "@/services/auth";
import { getApiBaseUrl, getToken, ApiError } from "@/services/api";

export const Route = createFileRoute("/login")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "Sign in — SOCVision" },
      {
        name: "description",
        content: "Sign in to the SOCVision Security Operations Center console.",
      },
      { property: "og:title", content: "Sign in — SOCVision" },
      {
        property: "og:description",
        content: "Sign in to the SOCVision Security Operations Center console.",
      },
    ],
  }),
  component: LoginPage,
});

function LoginPage() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [apiUrl, setApiUrl] = useState("");

  useEffect(() => {
    setApiUrl(getApiBaseUrl());
    if (getToken()) navigate({ to: "/dashboard", replace: true });
  }, [navigate]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
      navigate({ to: "/dashboard", replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.kind === "unauthorized") {
        setError("Invalid username or password.");
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Sign in failed.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <div className="flex items-center justify-center px-6 py-12">
        <form onSubmit={handleSubmit} className="w-full max-w-sm space-y-6">
          <div className="space-y-2">
            <span className="grid size-10 place-items-center rounded-lg bg-primary/15 text-primary ring-1 ring-primary/30">
              <Shield className="size-5" />
            </span>
            <h1 className="text-2xl font-semibold tracking-tight">SOCVision</h1>
            <p className="text-sm text-muted-foreground">Security Operations Center</p>
          </div>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <div className="relative">
                <Input
                  id="password"
                  type={show ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  disabled={loading}
                  className="pr-10"
                />
                <button
                  type="button"
                  onClick={() => setShow((s) => !s)}
                  aria-label={show ? "Hide password" : "Show password"}
                  className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground"
                >
                  {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                </button>
              </div>
            </div>
          </div>

          <div aria-live="polite" className="min-h-[1.25rem]">
            {error ? (
              <p className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-foreground">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-destructive" />
                {error}
              </p>
            ) : null}
          </div>

          <Button type="submit" className="w-full" disabled={loading}>
            {loading ? <Loader2 className="size-4 animate-spin" /> : <Lock className="size-4" />}
            {loading ? "Authenticating…" : "Sign In"}
          </Button>

          <p className="text-center font-mono text-[11px] text-muted-foreground">
            Backend: {apiUrl || "…"}
          </p>
        </form>
      </div>

      <div className="relative hidden overflow-hidden border-l border-border bg-sidebar lg:block">
        <div className="absolute inset-0 grid-backdrop" aria-hidden />
        <div className="relative flex h-full flex-col justify-center gap-8 px-12">
          <div className="space-y-3">
            <p className="font-mono text-[11px] tracking-[0.3em] text-primary uppercase">
              Threat Operations
            </p>
            <h2 className="max-w-sm text-3xl leading-tight font-semibold tracking-tight">
              Detect, triage and investigate security events in one console.
            </h2>
            <p className="max-w-sm text-sm text-muted-foreground">
              Incident severity scoring, MITRE ATT&CK mapping and automated log analysis — all
              served by your SOCVision backend.
            </p>
          </div>
          <dl className="grid max-w-sm grid-cols-2 gap-4">
            {[
              ["Severity model", "Critical → Low"],
              ["Risk scoring", "0 – 100"],
              ["Framework", "MITRE ATT&CK"],
              ["Analysis", "Log upload"],
            ].map(([label, value]) => (
              <div key={label} className="rounded-md border border-border bg-card/60 p-3">
                <dt className="text-[11px] tracking-wider text-muted-foreground uppercase">
                  {label}
                </dt>
                <dd className="mt-1 font-mono text-sm">{value}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </div>
  );
}
