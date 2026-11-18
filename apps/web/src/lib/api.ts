import type { ApiHealthResponse, AuthSessionResponse } from "@lumicsec/shared";

const apiBase = import.meta.env.VITE_API_BASE_URL ?? "";

async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (!headers.has("accept")) {
    headers.set("accept", "application/json");
  }

  const response = await fetch(apiBase + path, {
    ...init,
    headers,
    credentials: "include",
    cache: "no-store",
  });

  const payload: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const record = payload !== null && typeof payload === "object" ? payload as Record<string, unknown> : {};
    const message = typeof record.message === "string"
      ? record.message
      : typeof record.error === "string"
        ? record.error
        : "The request could not be completed.";
    throw new Error(message);
  }

  return payload as T;
}

export function getAuthSession() {
  return requestJson<AuthSessionResponse>("/auth/session");
}

export function getApiHealth() {
  return requestJson<ApiHealthResponse>("/healthz");
}

export function postJson<T>(path: string, body: unknown, csrfToken: string) {
  return requestJson<T>(path, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify(body),
  });
}
