import { request, setAuth, clearAuth, getToken, getUsername } from "./api";
import type { LoginResponse } from "@/types/soc";

export async function login(username: string, password: string): Promise<void> {
  const data = await request<LoginResponse>("/auth/login", {
    method: "POST",
    body: { username, password },
    auth: false,
  });
  if (!data?.access_token) {
    throw new Error("Backend did not return an access token.");
  }
  setAuth(data.access_token, username);
}

export function logout() {
  clearAuth();
}

export function isAuthenticated(): boolean {
  return Boolean(getToken());
}

export { getToken, getUsername };
