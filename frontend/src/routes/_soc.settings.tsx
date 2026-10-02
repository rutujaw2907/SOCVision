import { useEffect, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Panel, Field } from "@/components/soc/panel";
import {
  DEFAULT_API_URL,
  getApiBaseUrl,
  getToken,
  getUsername,
  setApiBaseUrl,
} from "@/services/api";
import { logout } from "@/services/auth";

export const Route = createFileRoute("/_soc/settings")({
  head: () => ({
    meta: [
      { title: "Settings — SOCVision" },
      {
        name: "description",
        content: "Manage your SOCVision profile, session and backend API configuration.",
      },
      { property: "og:title", content: "Settings — SOCVision" },
      {
        property: "og:description",
        content: "Manage your SOCVision profile, session and backend API configuration.",
      },
    ],
  }),
  component: SettingsPage,
});

function SettingsPage() {
  const navigate = useNavigate();
  const [apiUrl, setApiUrl] = useState("");
  const [username, setUsername] = useState("");
  const [tokenPresent, setTokenPresent] = useState(false);

  useEffect(() => {
    setApiUrl(getApiBaseUrl());
    setUsername(getUsername() ?? "");
    setTokenPresent(Boolean(getToken()));
  }, []);

  return (
    <div className="space-y-5">
      <header>
        <h2 className="text-xl font-semibold tracking-tight">Settings</h2>
        <p className="text-sm text-muted-foreground">
          Console configuration for this SOCVision workstation
        </p>
      </header>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Profile">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Username" value={username || "—"} />
            <Field label="Role" value="Security Analyst" />
          </div>
        </Panel>

        <Panel title="Authentication">
          <div className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Session" value={tokenPresent ? "Active JWT session" : "Signed out"} />
              <Field label="Token storage" value={<span className="font-mono">socvision_token</span>} />
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                logout();
                navigate({ to: "/login", replace: true });
              }}
            >
              Sign out of this session
            </Button>
          </div>
        </Panel>

        <Panel
          title="API Configuration"
          description="Base URL of the SOCVision FastAPI backend"
          className="lg:col-span-2"
        >
          <div className="space-y-3">
            <div className="space-y-2">
              <Label htmlFor="api-url">Backend URL</Label>
              <div className="flex flex-col gap-2 sm:flex-row">
                <Input
                  id="api-url"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder={DEFAULT_API_URL}
                  className="font-mono text-sm"
                />
                <Button
                  onClick={() => {
                    setApiBaseUrl(apiUrl);
                    setApiUrl(getApiBaseUrl());
                    toast.success("Backend URL updated");
                  }}
                >
                  Save
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    setApiBaseUrl(DEFAULT_API_URL);
                    setApiUrl(getApiBaseUrl());
                    toast.success("Backend URL reset to default");
                  }}
                >
                  Reset
                </Button>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              The default comes from the <span className="font-mono">VITE_API_URL</span>{" "}
              environment variable (currently{" "}
              <span className="font-mono">{DEFAULT_API_URL}</span>). No secrets are stored in the
              frontend.
            </p>
          </div>
        </Panel>

        <Panel title="Appearance" className="lg:col-span-2">
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Theme" value="SOC dark (default)" />
            <Field label="Density" value="Comfortable" />
          </div>
        </Panel>
      </div>
    </div>
  );
}
