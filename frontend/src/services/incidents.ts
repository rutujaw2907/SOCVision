import { fetchRecent } from "./dashboard";
import { api, getApiBaseUrl, getToken } from "./api";
import type { Incident } from "@/types/soc";

export const incidentKeys = {
  list: ["incidents", "list"] as const,

  detail: (id: string) =>
    ["incidents", "detail", id] as const,
};


type BackendIncident = {
  id: number | string;

  ip?: string | null;

  attack?: string | null;

  severity?: string | null;

  risk_score?: number | null;

  mitre_technique?: string | null;

  mitre_technique_name?: string | null;

  mitre_name?: string | null;

  path?: string | null;

  method?: string | null;

  status?: string | number | null;

  endpoint?: string | null;

  status_code?: number | null;

  timestamp?: string | null;

  created_at?: string | null;

  updated_at?: string | null;

  incident_status?: string | null;

  iocs?:
    | string
    | string[]
    | Record<string, unknown>
    | null;
};


function normalizeIocs(
  value: BackendIncident["iocs"],
): string[] {

  if (!value) {
    return [];
  }


  if (Array.isArray(value)) {
    return value.map(String);
  }


  if (typeof value === "object") {

    return Object.entries(value).map(
      ([key, item]) =>
        `${key}: ${String(item)}`,
    );

  }


  if (typeof value === "string") {

    try {

      const parsed =
        JSON.parse(value);


      if (Array.isArray(parsed)) {
        return parsed.map(String);
      }


      if (
        parsed &&
        typeof parsed === "object"
      ) {

        return Object.entries(
          parsed,
        ).map(
          ([key, item]) =>
            `${key}: ${String(item)}`,
        );

      }


      return [value];

    } catch {

      return value.trim()
        ? [value]
        : [];

    }

  }


  return [];
}


function normalizeIncident(
  incident: BackendIncident,
): Incident {

  const statusCode =
    incident.status_code ??
    (
      typeof incident.status === "number"
        ? incident.status
        : Number(incident.status)
    );


  return {

    id: incident.id,

    ip:
      incident.ip ??
      "Unknown",

    attack:
      incident.attack ??
      "Unknown",

    severity:
      incident.severity ??
      "Low",

    risk_score:
      incident.risk_score ??
      0,


    mitre_technique:
      incident.mitre_technique ??
      undefined,


    mitre_technique_name:
      incident.mitre_technique_name ??
      incident.mitre_name ??
      undefined,


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


    incident_status:
      (
        incident.incident_status ??
        "OPEN"
      ) as Incident["incident_status"],


    updated_at:
      incident.updated_at ??
      undefined,


    created_at:
      incident.created_at ??
      undefined,


    timestamp:
      incident.timestamp ??
      incident.created_at ??
      "",


    iocs:
      normalizeIocs(
        incident.iocs,
      ),

  };
}


function unwrap(
  data:
    | BackendIncident[]
    | {
        incidents: BackendIncident[];
      },
): BackendIncident[] {

  return Array.isArray(data)
    ? data
    : (
        data?.incidents ??
        []
      );

}


export async function listIncidents(
  signal?: AbortSignal,
): Promise<Incident[]> {

  const data =
    await fetchRecent(signal);


  return unwrap(
    data as
      | BackendIncident[]
      | {
          incidents: BackendIncident[];
        },
  ).map(
    normalizeIncident,
  );

}


export async function getIncident(
  id: string,
  signal?: AbortSignal,
): Promise<Incident | null> {

  try {

    const data =
      await api.get<BackendIncident>(
        `/incidents/${id}`,
        signal,
      );


    return normalizeIncident(
      data,
    );

  } catch {

    return null;

  }

}


export async function updateIncidentStatus(
  id: string,

  status:
    | "OPEN"
    | "INVESTIGATING"
    | "CONTAINED"
    | "RESOLVED",

  signal?: AbortSignal,
) {

  return api.patch<{
    message: string;
    id: number;
    incident_status: string;
    updated_at: string;
  }>(
    `/incidents/${id}/status`,
    {
      status,
    },
    signal,
  );

}


/**
 * Downloads the generated SOCVision
 * incident PDF report.
 */
export async function downloadIncidentReport(
  id: string,
): Promise<void> {

  const token = getToken();

  const response = await fetch(
    `${getApiBaseUrl()}/incidents/${id}/report`,
    {
      method: "GET",

      headers: token
        ? {
            Authorization:
              `Bearer ${token}`,
          }
        : {},
    },
  );


  if (!response.ok) {

    let message =
      "Unable to generate incident report.";

    try {

      const data =
        await response.json();

      if (
        typeof data?.detail ===
        "string"
      ) {
        message = data.detail;
      }

    } catch {
      /* Ignore non-JSON error */
    }

    throw new Error(message);
  }


  const blob =
    await response.blob();


  const url =
    window.URL.createObjectURL(
      blob,
    );


  const link =
    document.createElement(
      "a",
    );

  link.href = url;

  link.download =
    `SOCVision_Incident_${id}.pdf`;


  document.body.appendChild(
    link,
  );

  link.click();

  link.remove();


  window.URL.revokeObjectURL(
    url,
  );

}