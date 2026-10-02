import { fetchRecent } from "./dashboard";
import type { Incident } from "@/types/soc";

export const incidentKeys = {
  list: ["incidents", "list"] as const,
  detail: (id: string) => ["incidents", "detail", id] as const,
};

type BackendIncident = {
  id: number | string;
  ip?: string | null;
  attack?: string | null;
  severity?: string | null;
  risk_score?: number | null;
  mitre_technique?: string | null;
  mitre_technique_name?: string | null;

  // Backend names
  path?: string | null;
  method?: string | null;
  status?: string | number | null;

  // Frontend names, if already present
  endpoint?: string | null;
  status_code?: number | null;

  timestamp?: string | null;
  created_at?: string | null;

  // Backend stores this as JSON text
  iocs?: string | string[] | Record<string, unknown> | null;
};

function normalizeIocs(
  value: BackendIncident["iocs"],
): string[] {
  if (!value) return [];

  if (Array.isArray(value)) {
    return value.map(String);
  }

  if (typeof value === "object") {
    return Object.entries(value).map(
      ([key, item]) => `${key}: ${String(item)}`,
    );
  }

  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);

      if (Array.isArray(parsed)) {
        return parsed.map(String);
      }

      if (parsed && typeof parsed === "object") {
        return Object.entries(parsed).map(
          ([key, item]) => `${key}: ${String(item)}`,
        );
      }

      return [value];
    } catch {
      return value.trim() ? [value] : [];
    }
  }

  return [];
}

function normalizeIncident(
  incident: BackendIncident,
): Incident {
  const statusCode =
    incident.status_code ??
    (typeof incident.status === "number"
      ? incident.status
      : Number(incident.status));

  return {
    id: incident.id,
    ip: incident.ip ?? "Unknown",
    attack: incident.attack ?? "Unknown",
    severity: incident.severity ?? "Low",
    risk_score: incident.risk_score ?? 0,

    mitre_technique:
      incident.mitre_technique ?? undefined,

    mitre_technique_name:
      incident.mitre_technique_name ?? undefined,

    endpoint:
      incident.endpoint ??
      incident.path ??
      undefined,

    method:
      incident.method ??
      undefined,

    status_code:
      Number.isFinite(statusCode)
        ? statusCode
        : undefined,

    status:
      incident.status != null
        ? String(incident.status)
        : undefined,

    timestamp:
      incident.timestamp ??
      incident.created_at ??
      "",

    iocs: normalizeIocs(incident.iocs),
  };
}

function unwrap(
  data:
    | BackendIncident[]
    | { incidents: BackendIncident[] },
): BackendIncident[] {
  return Array.isArray(data)
    ? data
    : (data?.incidents ?? []);
}

/**
 * Get incidents from the backend.
 */
export async function listIncidents(
  signal?: AbortSignal,
): Promise<Incident[]> {
  const data = await fetchRecent(signal);

  return unwrap(data as BackendIncident[] | {
    incidents: BackendIncident[];
  }).map(normalizeIncident);
}

/**
 * Get a single incident by ID.
 */
export async function getIncident(
  id: string,
  signal?: AbortSignal,
): Promise<Incident | null> {
  const incidents = await listIncidents(signal);

  return (
    incidents.find(
      (incident) =>
        String(incident.id) === String(id),
    ) ?? null
  );
}