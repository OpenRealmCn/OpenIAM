import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Validates a post-login return URL to prevent open redirects.
 *
 * Only same-origin relative paths are accepted. Rejects protocol-relative
 * URLs (`//host`), backslash variants that browsers normalise to `//`
 * (`/\host`), and absolute URLs. Control characters and whitespace are
 * stripped first because browsers ignore them during URL parsing, which
 * would otherwise allow `/\tevil.com` style bypasses.
 */
export function safeReturnURL(returnTo: unknown, fallback: string): string {
  if (typeof returnTo !== "string" || returnTo === "") {
    return fallback;
  }

  // Browsers strip TAB, LF and CR anywhere in a URL before parsing.
  const candidate = returnTo.replace(/[\u0000-\u0020\u007f]/g, "");

  if (!candidate.startsWith("/")) return fallback;
  if (candidate.startsWith("//")) return fallback;
  if (candidate.includes("\\")) return fallback;

  // Final check: resolving against an arbitrary origin must keep that origin.
  try {
    const base = "https://openiam.invalid";
    const resolved = new URL(candidate, base);
    if (resolved.origin !== base) return fallback;
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return fallback;
  }
}
