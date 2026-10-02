import { createFileRoute, Outlet, redirect } from "@tanstack/react-router";
import { SocLayout } from "@/components/layout/soc-layout";
import { TOKEN_KEY } from "@/services/api";

export const Route = createFileRoute("/_soc")({
  ssr: false,
  beforeLoad: () => {
    if (typeof window !== "undefined" && !window.localStorage.getItem(TOKEN_KEY)) {
      throw redirect({ to: "/login" });
    }
  },
  component: () => (
    <SocLayout>
      <Outlet />
    </SocLayout>
  ),
});
