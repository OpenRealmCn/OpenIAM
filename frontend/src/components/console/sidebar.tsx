"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Cable,
  CircleUserRound,
  FileClock,
  ListChecks,
  LogOut,
  Settings,
  ShieldCheck,
  Users,
} from "lucide-react";

import { BrandMark } from "@/components/brand-mark";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/dashboard", label: "概览", icon: Activity },
  { href: "/users", label: "用户", icon: Users },
  { href: "/roles", label: "角色", icon: ShieldCheck },
  { href: "/permissions", label: "权限", icon: ListChecks },
  { href: "/oauth-clients", label: "OAuth 客户端", icon: Cable },
  { href: "/audit-logs", label: "审计日志", icon: FileClock },
  { href: "/profile", label: "我的资料", icon: CircleUserRound },
  { href: "/settings", label: "系统设置", icon: Settings },
];

export function ConsoleSidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const [signingOut, setSigningOut] = useState(false);

  async function handleLogout() {
    if (signingOut) return;
    setSigningOut(true);
    await fetch("/api/dev/session", { method: "DELETE" });
    router.push("/login");
    router.refresh();
  }

  return (
    <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-[var(--border)] bg-[var(--surface)] md:flex">
      <div className="flex h-16 items-center border-b border-[var(--border)] px-5">
        <BrandMark />
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        <p className="px-3 pb-2 font-mono text-[10px] uppercase tracking-[0.22em] text-[var(--faint)]">
          访问管理
        </p>
        {navItems.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(`${href}/`);
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors duration-150",
                active
                  ? "bg-[var(--surface-3)] font-medium text-[var(--fg-strong)]"
                  : "text-[var(--muted)] hover:bg-[var(--surface-2)] hover:text-[var(--fg)]",
              )}
            >
              {active && (
                <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-[var(--accent)]" />
              )}
              <Icon
                className={cn(
                  "size-4 transition-colors",
                  active
                    ? "text-[var(--fg-strong)]"
                    : "text-[var(--faint)] group-hover:text-[var(--muted)]",
                )}
                strokeWidth={1.8}
              />
              {label}
              {active && (
                <span className="ml-auto size-1 rounded-full bg-[var(--accent)]" />
              )}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-[var(--border)] p-4">
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-2)] p-3">
          <div className="flex items-center gap-2.5">
            <span className="grid size-8 shrink-0 place-items-center rounded-full bg-[var(--surface-3)] text-xs font-medium text-[var(--fg)]">
              管
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-[var(--fg)]">
                dev-admin
              </p>
              <p className="flex items-center gap-1.5 text-[11px] text-[var(--faint)]">
                <span className="pulse-dot size-1.5 rounded-full bg-emerald-500" />
                开发模式会话
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            disabled={signingOut}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-[var(--border-strong)] py-1.5 text-xs text-[var(--muted)] transition-colors duration-150 hover:border-red-500/40 hover:bg-red-500/10 hover:text-red-400 disabled:opacity-60"
          >
            <LogOut className="size-3.5" />
            {signingOut ? "退出中…" : "退出登录"}
          </button>
        </div>
      </div>
    </aside>
  );
}
