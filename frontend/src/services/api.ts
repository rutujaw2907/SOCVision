/**
 * Centralised SOCVision API client.
 *
 * - Base URL comes from VITE_API_URL (overridable at runtime in Settings).
 * - Attaches `Authorization: Bearer <jwt>` from localStorage on protected calls.
 * - On 401: clears auth and redirects to /login.
 */

export const TOKEN_KEY = "socvision_token";
export const USER_KEY = "socvision_user";
export const API_URL_KEY = "socvision_api_url";

export const DEFAULT_API_URL =
  (import.meta.env.VITE_API_URL as string | undefined) ?? "http://127.0.0.1:8000";

export function getApiBaseUrl(): string {
  if (typeof window !== "undefined") {
    const override = window.localStorage.getItem(API_URL_KEY);
    if (override) return override.replace(/\/$/, "");
  }
  return DEFAULT_API_URL.replace(/\/$/, "");
}

export function setApiBaseUrl(url: string) {
  if (typeof window === "undefined") return;
  const trimmed = url.trim().replace(/\/$/, "");
  if (!trimmed || trimmed === DEFAULT_API_URL.replace(/\/$/, "")) {
    window.localStorage.removeItem(API_URL_KEY);
  } else {
    window.localStorage.setItem(API_URL_KEY, trimmed);
  }
}

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

export function getUsername(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(USER_KEY);
}

export function setAuth(token: string, username: string) {
  window.localStorage.setItem(TOKEN_KEY, token);
  window.localStorage.setItem(USER_KEY, username);
}

export function clearAuth() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(USER_KEY);
}

export type ApiErrorKind =
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "server"
  | "network"
  | "unknown";

export class ApiError extends Error {
  status: number;
  kind: ApiErrorKind;

  constructor(message: string, status: number, kind: ApiErrorKind) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.kind = kind;
  }
}

function kindFor(status: number): ApiErrorKind {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status >= 500) return "server";
  return "unknown";
}

function messageFor(kind: ApiErrorKind, detail?: string): string {
  if (detail) return detail;
  switch (kind) {
    case "unauthorized":
      return "Your session has expired. Please sign in again.";
    case "forbidden":
      return "You do not have permission to view this resource.";
    case "not_found":
      return "The requested resource was not found.";
    case "server":
      return "The SOCVision backend returned a server error.";
    case "network":
      return "Unable to connect to SOCVision backend.";
    default:
      return "Unexpected error while contacting the SOCVision backend.";
  }
}

function handleUnauthorized() {
  clearAuth();
  if (typeof window !== "undefined" && window.location.pathname !== "/login") {
    window.location.replace("/login");
  }
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  formData?: FormData;
  /** Attach the bearer token (default: true). */
  auth?: boolean;
  signal?: AbortSignal;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { method = "GET", body, formData, auth = true, signal } = options;
  const headers: Record<string, string> = {};

  if (auth) {
    const token = getToken();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  if (body !== undefined && !formData) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(`${getApiBaseUrl()}${path}`, {
      method,
      headers,
      body: formData ?? (body !== undefined ? JSON.stringify(body) : undefined),
      signal,
    });
  } catch {
    throw new ApiError(messageFor("network"), 0, "network");
  }

  if (response.status === 401) {
    handleUnauthorized();
    throw new ApiError(messageFor("unauthorized"), 401, "unauthorized");
  }

  if (!response.ok) {
    const kind = kindFor(response.status);
    let detail: string | undefined;
    try {
      const data = (await response.json()) as { detail?: unknown; message?: unknown };
      const raw = data.detail ?? data.message;
      if (typeof raw === "string") detail = raw;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(messageFor(kind, detail), response.status, kind);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  post: <T>(path: string, body?: unknown, signal?: AbortSignal) =>
    request<T>(path, { method: "POST", body, signal }),
  upload: <T>(path: string, formData: FormData, signal?: AbortSignal) =>
    request<T>(path, { method: "POST", formData, signal }),
};
