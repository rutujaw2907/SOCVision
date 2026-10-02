import { api } from "./api";
import type { DashboardStats, Incident, TimelineEvent } from "@/types/soc";

export const dashboardKeys = {
  stats: ["dashboard", "stats"] as const,
  recent: ["dashboard", "recent"] as const,
  timeline: ["dashboard", "timeline"] as const,
};

type BackendStats = {
  total_incidents?: number;
  severity?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
  attack_types?: Record<string, number>;
  top_attacker_ips?: Record<string, number>;
};

export async function fetchStats(
  signal?: AbortSignal
): Promise<DashboardStats> {
  const data = await api.get<BackendStats>("/dashboard/stats", signal);

  return {
    total_incidents: data.total_incidents ?? 0,
    critical: data.severity?.critical ?? 0,
    high: data.severity?.high ?? 0,
    medium: data.severity?.medium ?? 0,
    low: data.severity?.low ?? 0,
    attack_types: data.attack_types ?? {},
    top_ips: Object.entries(data.top_attacker_ips ?? {}).map(
      ([ip, count]) => ({
        ip,
        count: Number(count),
      })
    ),
    mitre: [],
  };
}

export function fetchRecent(signal?: AbortSignal) {
  return api.get<Incident[] | { incidents: Incident[] }>(
    "/dashboard/recent",
    signal
  );
}

export function fetchTimeline(signal?: AbortSignal) {
  return api.get<TimelineEvent[] | { events: TimelineEvent[] }>(
    "/dashboard/timeline",
    signal
  );
}