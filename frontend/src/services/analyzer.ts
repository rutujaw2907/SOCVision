import { api } from "./api";
import type { AnalyzerResult } from "@/types/soc";

/** POST /upload/ — multipart/form-data with `file`, bearer token attached. */
export function analyzeLog(file: File, signal?: AbortSignal): Promise<AnalyzerResult> {
  const formData = new FormData();
  formData.append("file", file);
  return api.upload<AnalyzerResult>("/upload/", formData, signal);
}
