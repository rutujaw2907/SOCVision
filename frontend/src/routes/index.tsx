import { createFileRoute, redirect } from "@tanstack/react-router";
import { TOKEN_KEY } from "@/services/api";

export const Route = createFileRoute("/")({
  ssr: false,
  head: () => ({
    meta: [
      { title: "SOCVision — Security Operations Center" },
      {
        name: "description",
        content:
          "SOCVision is a security operations console for incident triage, log analysis and MITRE ATT&CK coverage.",
      },
      { property: "og:title", content: "SOCVision — Security Operations Center" },
      {
        property: "og:description",
        content:
          "SOCVision is a security operations console for incident triage, log analysis and MITRE ATT&CK coverage.",
      },
    ],
  }),
  beforeLoad: () => {
    if (typeof window === "undefined") return;
    throw redirect({ to: window.localStorage.getItem(TOKEN_KEY) ? "/dashboard" : "/login" });
  },
  component: () => null,
});
