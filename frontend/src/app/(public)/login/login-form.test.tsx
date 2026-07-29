import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { LoginForm } from "./login-form";

// ── Next.js mocks ──────────────────────────────────────────────────────────
const mockPush = vi.fn();
const mockRefresh = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush, refresh: mockRefresh }),
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
    ...props
  }: {
    href: string;
    children: React.ReactNode;
    [key: string]: unknown;
  }) => (
    <a href={href} {...props}>
      {children}
    </a>
  ),
}));

// ── fetch mock ─────────────────────────────────────────────────────────────
const mockFetch = vi.fn();
global.fetch = mockFetch as unknown as typeof fetch;

beforeEach(() => {
  mockPush.mockReset();
  mockRefresh.mockReset();
  mockFetch.mockReset();
});

// ── helpers ────────────────────────────────────────────────────────────────
function okSessionResponse() {
  return Promise.resolve(
    new Response(JSON.stringify({ ok: true }), { status: 200 }),
  );
}

function failSessionResponse() {
  return Promise.resolve(new Response(null, { status: 500 }));
}

// ── tests ──────────────────────────────────────────────────────────────────

describe("LoginForm rendering", () => {
  it("renders login heading", () => {
    render(<LoginForm />);
    expect(
      screen.getByRole("heading", { name: /登录 OpenIAM/i }),
    ).toBeInTheDocument();
  });

  it("renders username and password inputs", () => {
    render(<LoginForm />);
    expect(
      screen.getByPlaceholderText("name@openrealm.io"),
    ).toBeInTheDocument();
    expect(screen.getByPlaceholderText("••••••••••••")).toBeInTheDocument();
  });

  it("renders Feishu login link pointing to backend", () => {
    render(<LoginForm />);
    const feishuLink = screen.getByRole("link", { name: /使用飞书登录/i });
    expect(feishuLink).toHaveAttribute(
      "href",
      expect.stringContaining("/api/v1/auth/feishu"),
    );
  });

  it("renders back-to-home link", () => {
    render(<LoginForm />);
    const homeLink = screen.getByRole("link", { name: /返回首页/i });
    expect(homeLink).toHaveAttribute("href", "/");
  });

  it("renders dev mode notice in development", () => {
    render(<LoginForm />);
    expect(screen.getByText(/开发模式/)).toBeInTheDocument();
  });
});

describe("LoginForm error display", () => {
  it("shows error message for known error code", () => {
    render(<LoginForm error="invalid_state" />);
    expect(
      screen.getByText(/飞书登录状态已失效，请重新发起登录。/),
    ).toBeInTheDocument();
  });

  it("shows nothing for unknown error code", () => {
    render(<LoginForm error="totally_unknown_code" />);
    // No error paragraph should appear
    expect(
      screen.queryByText(/ffa198/), // the error text color class indicator
    ).not.toBeInTheDocument();
    // More precisely: the error paragraph uses a specific text class
    const errorParagraphs = document
      .querySelectorAll("p")
      [0]?.textContent?.includes("totally_unknown_code");
    expect(errorParagraphs).toBeFalsy();
  });

  it("shows no error when error prop is omitted", () => {
    render(<LoginForm />);
    // None of the error messages from the map should appear
    expect(
      screen.queryByText(/飞书登录缺少必要参数/),
    ).not.toBeInTheDocument();
  });
});

describe("LoginForm submit (dev mode)", () => {
  it("redirects to /dashboard on successful login without returnTo", async () => {
    mockFetch.mockResolvedValueOnce(okSessionResponse());

    render(<LoginForm />);
    const form = document.querySelector("form")!;
    fireEvent.submit(form);

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith("/api/dev/session", {
        method: "POST",
      });
    });
    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith("/dashboard");
    });
    expect(mockRefresh).toHaveBeenCalledOnce();
  });

  it("redirects to safe returnTo on success", async () => {
    mockFetch.mockResolvedValueOnce(okSessionResponse());

    render(<LoginForm returnTo="/roles" />);
    fireEvent.submit(document.querySelector("form")!);

    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith("/roles");
    });
  });

  it("falls back to /dashboard for malicious returnTo", async () => {
    mockFetch.mockResolvedValueOnce(okSessionResponse());

    render(<LoginForm returnTo="//evil.com" />);
    fireEvent.submit(document.querySelector("form")!);

    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("falls back to /dashboard for backslash redirect attempt", async () => {
    mockFetch.mockResolvedValueOnce(okSessionResponse());

    render(<LoginForm returnTo="/\\evil.com" />);
    fireEvent.submit(document.querySelector("form")!);

    await waitFor(() => {
      expect(mockPush).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("shows submit button as loading while request is in-flight", async () => {
    // Delay the response so we can observe the loading state
    let resolve!: (r: Response) => void;
    mockFetch.mockReturnValueOnce(new Promise((r) => (resolve = r)));

    render(<LoginForm />);
    const button = screen.getByRole("button", { name: /验证身份/i });
    expect(button).not.toBeDisabled();

    fireEvent.submit(document.querySelector("form")!);

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /验证中/i })).toBeDisabled();
    });

    // Resolve and verify normal state returns
    resolve(okSessionResponse());
    await waitFor(() => {
      expect(mockPush).toHaveBeenCalled();
    });
  });

  it("re-enables button on failed request", async () => {
    mockFetch.mockResolvedValueOnce(failSessionResponse());

    render(<LoginForm />);
    fireEvent.submit(document.querySelector("form")!);

    await waitFor(() => {
      expect(
        screen.getByRole("button", { name: /验证身份/i }),
      ).not.toBeDisabled();
    });
    expect(mockPush).not.toHaveBeenCalled();
  });

  it("does not call fetch twice on double submit", async () => {
    let resolve!: (r: Response) => void;
    mockFetch.mockReturnValueOnce(new Promise((r) => (resolve = r)));

    render(<LoginForm />);
    const form = document.querySelector("form")!;
    fireEvent.submit(form);
    fireEvent.submit(form); // second submit while first is in-flight

    resolve(okSessionResponse());
    await waitFor(() => expect(mockPush).toHaveBeenCalled());

    expect(mockFetch).toHaveBeenCalledOnce();
  });
});
