export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low";

export const SEVERITIES: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
];

export function normalizeSeverity(
  value: string | null | undefined,
): Severity {
  const v = (
    value ?? ""
  ).toLowerCase();

  if (
    v === "critical" ||
    v === "high" ||
    v === "medium" ||
    v === "low"
  ) {
    return v;
  }

  return "low";
}

export function severityFromScore(
  score: number,
): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";

  return "low";
}


/** POST /auth/login */
export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
}


/** GET /dashboard/stats */
export interface DashboardStats {
  total_incidents: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  attack_types?:
    | Record<string, number>
    | AttackTypeCount[];
  top_ips?: TopAttackerIp[];
  mitre?: MitreActivity[];
}

export interface AttackTypeCount {
  attack: string;
  count: number;
}

export interface TopAttackerIp {
  ip: string;
  count: number;
  severity?: string;
  risk_score?: number;
}

export interface MitreActivity {
  technique: string;
  technique_name: string;
  attack?: string;
  count: number;
}


/** Incident workflow */
export type IncidentStatus =
  | "OPEN"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED";


/** GET /dashboard/recent / GET /incidents/{id} */
export interface Incident {
  id: number | string;

  ip: string;

  attack: string;

  severity: string;

  risk_score: number;

  mitre_technique?: string;

  mitre_technique_name?: string;

  endpoint?: string;

  method?: string;

  status_code?: number;

  /**
   * HTTP status code.
   * Example: 200, 401, 403.
   */
  status?: string;

  /**
   * SOCVision incident workflow status.
   */
  incident_status?: IncidentStatus;

  timestamp: string;

  created_at?: string;

  updated_at?: string;

  iocs?: string[];
}


/** Timeline */
export interface TimelineEvent {
  id?: number | string;
  attack: string;
  severity: string;
  ip: string;
  endpoint?: string;
  mitre_technique?: string;
  timestamp: string;
}


/** POST /upload/ */
export interface AnalyzerThreat {
  attack: string;
  severity: string;
  risk_score: number;
  confidence?: number;
  mitre_technique?: string;
  reason?: string;
  evidence?: string;
  ip?: string;
}

export interface AnalyzerResult {
  file?: string;
  filename?: string;
  log_type?: string;
  total_logs?: number;
  threats_found?: number;
  risk_severity?: string;
  risk_score?: number;
  threats?: AnalyzerThreat[];
}


/** POST /ai/analyst/{incident_id} */
export interface AIAnalystResponse {
  incident_id: number;
  available: boolean;
  model?: string;
  analysis?: string;
  error?: string;
}