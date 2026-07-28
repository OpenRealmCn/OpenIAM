const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

let csrfToken: string | null = null;

/**
 * Store the CSRF token obtained from /auth/login or /auth/me.
 * The token is sent in the X-CSRF-Token header on all state-changing requests.
 */
export function setCSRFToken(token: string) {
  csrfToken = token;
}

/**
 * Clear the stored CSRF token (e.g., on logout).
 */
export function clearCSRFToken() {
  csrfToken = null;
}

export class APIError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
  ) {
    super(`API request failed with status ${status}`);
  }
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(init.body ? { "Content-Type": "application/json" } : {}),
  };

  // Add CSRF token for state-changing requests
  const method = init.method?.toUpperCase() || "GET";
  if (csrfToken && ["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      ...headers,
      ...init.headers,
    },
  });

  if (!response.ok) {
    throw new APIError(response.status, await readBody(response));
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

async function readBody(response: Response): Promise<unknown> {
  if (response.headers.get("content-type")?.includes("application/json")) {
    return response.json();
  }
  return response.text();
}
