import { NextRequest, NextResponse } from "next/server";

const sessionCookieName =
  process.env.OPENIAM_SESSION_COOKIE_NAME ?? "openiam_session";

const protectedPrefixes = [
  "/dashboard",
  "/users",
  "/roles",
  "/permissions",
  "/oauth-clients",
  "/audit-logs",
  "/settings",
  "/profile",
];

export function proxy(request: NextRequest) {
  const session = request.cookies.get(sessionCookieName)?.value;
  const { pathname, search } = request.nextUrl;

  const isProtected = protectedPrefixes.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`),
  );

  if (isProtected && !session) {
    const loginURL = new URL("/login", request.url);
    loginURL.searchParams.set("returnTo", `${pathname}${search}`);
    return NextResponse.redirect(loginURL);
  }

  if (pathname === "/login" && session) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/users/:path*",
    "/roles/:path*",
    "/permissions/:path*",
    "/oauth-clients/:path*",
    "/audit-logs/:path*",
    "/settings/:path*",
    "/profile/:path*",
    "/login",
  ],
};
