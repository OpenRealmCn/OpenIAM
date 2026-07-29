import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiFetch, setCSRFToken, clearCSRFToken, APIError } from "./api-client";

// Mock global fetch
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function emptyResponse(status = 204) {
  return new Response(null, { status });
}

beforeEach(() => {
  mockFetch.mockReset();
  clearCSRFToken();
});

describe("apiFetch", () => {
  it("sends GET request to correct URL with credentials", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ ok: true }));

    await apiFetch("/api/v1/users");

    expect(mockFetch).toHaveBeenCalledOnce();
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe("http://localhost:8080/api/v1/users");
    expect(init.credentials).toBe("include");
  });

  it("returns parsed JSON on success", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ items: [1, 2, 3] }));

    const result = await apiFetch<{ items: number[] }>("/api/v1/items");

    expect(result).toEqual({ items: [1, 2, 3] });
  });

  it("returns undefined for 204 No Content", async () => {
    mockFetch.mockResolvedValueOnce(emptyResponse(204));

    const result = await apiFetch("/api/v1/logout");

    expect(result).toBeUndefined();
  });

  it("throws APIError on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: { code: "NOT_FOUND", message: "Not found" } }, 404),
    );

    await expect(apiFetch("/api/v1/missing")).rejects.toBeInstanceOf(APIError);
  });

  it("APIError carries status and body", async () => {
    const errorBody = { error: { code: "FORBIDDEN", message: "Denied" } };
    mockFetch.mockResolvedValueOnce(jsonResponse(errorBody, 403));

    try {
      await apiFetch("/api/v1/protected");
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(APIError);
      expect((e as APIError).status).toBe(403);
      expect((e as APIError).body).toEqual(errorBody);
    }
  });
});

describe("CSRF token management", () => {
  it("does NOT send X-CSRF-Token on GET requests even when token is set", async () => {
    setCSRFToken("my-csrf-token");
    mockFetch.mockResolvedValueOnce(jsonResponse({}));

    await apiFetch("/api/v1/users");

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("sends X-CSRF-Token on POST when token is set", async () => {
    setCSRFToken("my-csrf-token");
    mockFetch.mockResolvedValueOnce(jsonResponse({ id: "new-user" }, 201));

    await apiFetch("/api/v1/users", {
      method: "POST",
      body: JSON.stringify({ username: "alice" }),
    });

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBe("my-csrf-token");
  });

  it("sends X-CSRF-Token on PUT", async () => {
    setCSRFToken("my-csrf-token");
    mockFetch.mockResolvedValueOnce(jsonResponse({}));

    await apiFetch("/api/v1/roles/admin/permissions", {
      method: "PUT",
      body: JSON.stringify({ permissions: [] }),
    });

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBe("my-csrf-token");
  });

  it("sends X-CSRF-Token on PATCH", async () => {
    setCSRFToken("tok");
    mockFetch.mockResolvedValueOnce(jsonResponse({}));

    await apiFetch("/api/v1/users/1", {
      method: "PATCH",
      body: JSON.stringify({ status: "active" }),
    });

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBe("tok");
  });

  it("sends X-CSRF-Token on DELETE", async () => {
    setCSRFToken("tok");
    mockFetch.mockResolvedValueOnce(emptyResponse());

    await apiFetch("/api/v1/users/1", { method: "DELETE" });

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBe("tok");
  });

  it("does NOT send X-CSRF-Token on POST when no token is set", async () => {
    // clearCSRFToken called in beforeEach
    mockFetch.mockResolvedValueOnce(jsonResponse({}));

    await apiFetch("/api/v1/users", {
      method: "POST",
      body: JSON.stringify({}),
    });

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("clears token after clearCSRFToken", async () => {
    setCSRFToken("to-be-cleared");
    clearCSRFToken();

    mockFetch.mockResolvedValueOnce(jsonResponse({}));

    await apiFetch("/api/v1/users", {
      method: "POST",
      body: JSON.stringify({}),
    });

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBeUndefined();
  });

  it("is case-insensitive for HTTP method", async () => {
    setCSRFToken("tok");
    mockFetch.mockResolvedValueOnce(jsonResponse({}));

    await apiFetch("/api/v1/users", {
      method: "post",
      body: JSON.stringify({}),
    });

    const headers = mockFetch.mock.calls[0][1].headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBe("tok");
  });
});
