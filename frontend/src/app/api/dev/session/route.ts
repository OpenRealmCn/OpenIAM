import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";

const cookieName =
  process.env.OPENIAM_SESSION_COOKIE_NAME ?? "openiam_session";

function notFound() {
  return NextResponse.json(
    { error: { code: "NOT_FOUND", message: "Not found" } },
    { status: 404 },
  );
}

export async function POST() {
  if (process.env.NODE_ENV === "production") {
    return notFound();
  }

  const response = NextResponse.json({ data: { sessionId: randomUUID() } });
  response.cookies.set(cookieName, randomUUID(), {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    path: "/",
    maxAge: 60 * 60 * 12,
  });
  return response;
}

export async function DELETE() {
  if (process.env.NODE_ENV === "production") {
    return notFound();
  }

  const response = NextResponse.json({ data: { revoked: true } });
  response.cookies.set(cookieName, "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return response;
}
