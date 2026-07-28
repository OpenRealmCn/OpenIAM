import { NextRequest, NextResponse } from "next/server";

const sessionCookieName =
  process.env.OPENIAM_SESSION_COOKIE_NAME ?? "openiam_session";

export function proxy(request: NextRequest) {
  const session = request.cookies.get(sessionCookieName)?.value;
  const { pathname, search } = request.nextUrl;

  if (pathname.startsWith("/dashboard") && !session) {
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
  matcher: ["/dashboard/:path*", "/login"],
};
