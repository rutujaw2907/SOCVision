import { useState, type ReactNode } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  Bell,
  Crosshair,
  FileSearch,
  LayoutDashboard,
  LogOut,
  Menu,
  Search,
  Settings as SettingsIcon,
  Shield,
  ShieldAlert,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Sheet,
  SheetContent,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";

import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

import { logout } from "@/services/auth";
import { getUsername } from "@/services/api";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/incidents", label: "Incidents", icon: ShieldAlert },
  { to: "/analyzer", label: "Log Analyzer", icon: FileSearch },
  { to: "/mitre", label: "MITRE ATT&CK", icon: Crosshair },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
] as const;

const TITLES: Record<string, string> = {
  "/dashboard": "Security Operations Center",
  "/incidents": "Security Incidents",
  "/analyzer": "Log Analyzer",
  "/mitre": "MITRE ATT&CK Activity",
  "/settings": "Settings",
};

function Brand() {
  return (
    <Link
      to="/dashboard"
      className="flex items-center gap-2.5 px-4 py-4"
    >
      <span className="grid size-8 place-items-center rounded-md bg-primary/15 text-primary ring-1 ring-primary/30">
        <Shield className="size-4" />
      </span>

      <span className="leading-tight">
        <span className="block text-sm font-semibold tracking-tight">
          SOCVision
        </span>

        <span className="block text-[10px] tracking-wider text-muted-foreground uppercase">
          Security Ops
        </span>
      </span>
    </Link>
  );
}

function NavItems({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = useRouterState({
    select: (s) => s.location.pathname,
  });

  return (
    <nav className="flex-1 space-y-1 px-3">
      {NAV.map(({ to, label, icon: Icon }) => {
        const active =
          pathname === to || pathname.startsWith(`${to}/`);

        return (
          <Link
            key={to}
            to={to}
            onClick={onNavigate}
            className={cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
              active
                ? "bg-sidebar-accent text-sidebar-accent-foreground ring-1 ring-border"
                : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
            )}
          >
            <Icon
              className={cn(
                "size-4",
                active && "text-primary",
              )}
            />

            {label}
          </Link>
        );
      })}
    </nav>
  );
}

function SidebarFooter() {
  const navigate = useNavigate();
  const username = getUsername() ?? "operator";

  const handleLogout = () => {
    logout();
    navigate({
      to: "/login",
      replace: true,
    });
  };

  return (
    <div className="space-y-3 border-t border-sidebar-border p-3">
      <div className="flex items-center gap-2 rounded-md bg-sidebar-accent/50 px-3 py-2">
        <span className="relative flex size-2">
          <span className="absolute inline-flex size-full animate-ping rounded-full bg-online opacity-60" />
          <span className="relative inline-flex size-2 rounded-full bg-online" />
        </span>

        <span className="text-xs text-muted-foreground">
          System status: operational
        </span>
      </div>

      <div className="flex items-center gap-3 px-1">
        <span className="grid size-8 place-items-center rounded-full bg-muted font-mono text-xs uppercase">
          {username.slice(0, 2)}
        </span>

        <div className="min-w-0 flex-1">
          <p className="truncate text-sm">
            {username}
          </p>

          <p className="text-[11px] text-muted-foreground">
            Security Analyst
          </p>
        </div>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Sign out"
              onClick={handleLogout}
            >
              <LogOut className="size-4" />
            </Button>
          </TooltipTrigger>

          <TooltipContent>
            Sign out
          </TooltipContent>
        </Tooltip>
      </div>
    </div>
  );
}

export function SocLayout({
  children,
}: {
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);

  const pathname = useRouterState({
    select: (s) => s.location.pathname,
  });

  const title =
    TITLES[pathname] ??
    (pathname.startsWith("/incidents/")
      ? "Incident Investigation"
      : "SOCVision");

  return (
    <TooltipProvider>
      <div className="flex min-h-screen bg-background">

        {/* Desktop Sidebar */}
        <aside className="hidden w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar lg:flex">
          <Brand />

          <NavItems />

          <SidebarFooter />
        </aside>

        {/* Main Content */}
        <div className="flex min-w-0 flex-1 flex-col">

          {/* Header */}
          <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-background/85 px-4 backdrop-blur">

            {/* Mobile menu */}
            <Sheet
              open={open}
              onOpenChange={setOpen}
            >
              <SheetTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon"
                  className="lg:hidden"
                  aria-label="Open navigation"
                >
                  <Menu className="size-5" />
                </Button>
              </SheetTrigger>

              <SheetContent
                side="left"
                className="w-64 bg-sidebar p-0"
              >
                <SheetTitle className="sr-only">
                  Navigation
                </SheetTitle>

                <div className="flex h-full flex-col">
                  <Brand />

                  <NavItems
                    onNavigate={() => setOpen(false)}
                  />

                  <SidebarFooter />
                </div>
              </SheetContent>
            </Sheet>

            {/* Page title */}
            <h1 className="truncate text-sm font-semibold tracking-tight">
              {title}
            </h1>

            {/* Header actions */}
            <div className="ml-auto flex items-center gap-2">

              {/* Search */}
              <div className="relative hidden md:block">
                <Search className="absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />

                <Input
                  placeholder="Search IP, attack, technique"
                  className="h-8 w-56 pl-8 text-xs"
                  aria-label="Search"
                />
              </div>

              {/* Monitoring status */}
              <span className="hidden items-center gap-1.5 rounded-md border border-border px-2 py-1 text-[11px] text-muted-foreground sm:flex">
                <Activity className="size-3 text-online" />
                Monitoring
              </span>

              {/* Notifications */}
              <Button
                variant="ghost"
                size="icon"
                aria-label="Notifications"
              >
                <Bell className="size-4" />
              </Button>

              {/* User avatar */}
              <span className="grid size-8 place-items-center rounded-full bg-muted font-mono text-xs uppercase">
                {(getUsername() ?? "op").slice(0, 2)}
              </span>

            </div>
          </header>

          {/* Page */}
          <main className="flex-1 p-4 lg:p-6">
            {children}
          </main>

        </div>
      </div>
    </TooltipProvider>
  );
}