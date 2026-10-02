import { api } from "./api";
import type { AIAnalystResponse } from "@/types/soc";

export async function analyzeIncidentWithAI(
  incidentId: string,
  signal?: AbortSignal,
): Promise<AIAnalystResponse> {
  return api.post<AIAnalystResponse>(
    `/ai/analyst/${incidentId}`,
    undefined,
    signal,
  );
}