import { describe, it, expect } from "vitest";
import { safeReturnURL } from "./utils";

describe("safeReturnURL", () => {
  const fallback = "/dashboard";

  it("accepts valid relative path", () => {
    expect(safeReturnURL("/users", fallback)).toBe("/users");
    expect(safeReturnURL("/users?page=2", fallback)).toBe("/users?page=2");
    expect(safeReturnURL("/roles#permissions", fallback)).toBe(
      "/roles#permissions",
    );
  });

  it("rejects non-string input", () => {
    expect(safeReturnURL(null, fallback)).toBe(fallback);
    expect(safeReturnURL(undefined, fallback)).toBe(fallback);
    expect(safeReturnURL(123, fallback)).toBe(fallback);
    expect(safeReturnURL({}, fallback)).toBe(fallback);
  });

  it("rejects empty string", () => {
    expect(safeReturnURL("", fallback)).toBe(fallback);
  });

  it("rejects protocol-relative URLs", () => {
    expect(safeReturnURL("//evil.com", fallback)).toBe(fallback);
    expect(safeReturnURL("//evil.com/path", fallback)).toBe(fallback);
  });

  it("rejects backslash tricks", () => {
    expect(safeReturnURL("/\\evil.com", fallback)).toBe(fallback);
    expect(safeReturnURL("/\\\\evil.com", fallback)).toBe(fallback);
  });

  it("rejects absolute URLs", () => {
    expect(safeReturnURL("https://evil.com", fallback)).toBe(fallback);
    expect(safeReturnURL("http://evil.com", fallback)).toBe(fallback);
  });

  it("rejects URLs not starting with /", () => {
    expect(safeReturnURL("users", fallback)).toBe(fallback);
    expect(safeReturnURL("../admin", fallback)).toBe(fallback);
  });

  it("strips control characters before validation", () => {
    // \t (tab) is stripped, leaving /evil.com which is valid
    expect(safeReturnURL("/\tevil.com", fallback)).toBe("/evil.com");
    // Backslash + tab: after stripping tab, backslash remains and is rejected
    expect(safeReturnURL("/\\\tevil.com", fallback)).toBe(fallback);
    // Double-slash with control char injected: after stripping, //evil.com is rejected
    expect(safeReturnURL("/\t/evil.com", fallback)).toBe(fallback);
  });

  it("rejects javascript: protocol", () => {
    expect(safeReturnURL("javascript:alert(1)", fallback)).toBe(fallback);
  });

  it("normalizes valid paths through URL constructor", () => {
    // URL normalization should preserve valid paths
    expect(safeReturnURL("/users/../roles", fallback)).toBe("/roles");
    expect(safeReturnURL("/./users", fallback)).toBe("/users");
  });

  it("preserves query string and hash", () => {
    expect(safeReturnURL("/users?id=1&role=admin#top", fallback)).toBe(
      "/users?id=1&role=admin#top",
    );
  });
});
