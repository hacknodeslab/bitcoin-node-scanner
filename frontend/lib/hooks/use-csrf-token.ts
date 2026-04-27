"use client";

import useSWRImmutable from "swr/immutable";
import { fetchCsrfToken } from "../api/endpoints";

/**
 * Fetches the CSRF token once and stores it in the API client's module
 * memory. Subsequent mutating requests pick it up automatically. Use this
 * hook at the application root so the token is loaded before any POST.
 */
export function useCsrfToken() {
  const { data, error, isLoading } = useSWRImmutable(
    "/api/v1/csrf-token",
    () => fetchCsrfToken(),
  );
  return { token: data ?? null, error, isLoading };
}
