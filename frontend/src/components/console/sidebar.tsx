"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Cable,
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
    <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-[#1f1f1f] bg-[#050505] md:flex">
      <div className="flex h-16 items-center border-b border-[#1f1f1f] px-5">
        <BrandMark />
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-4">
        <p className="px-3 pb-2 font-mono text-[10px] uppercase tracking-[0.22em] text-[#525252]">
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
                  ? "bg-[#1a1a1a] font-medium text-white"
                  : "text-[#8a8a8a] hover:bg-[#111111] hover:text-[#ededed]",
              )}
            >
              {active && (
                <span className="absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-[var(--accent-ui)]" />
              )}
              <Icon
                className={cn(
                  "size-4 transition-colors",
                  active
                    ? "text-white"
                    : "text-[#666666] group-hover:text-[#a1a1a1]",
                )}
                strokeWidth={1.8}
              />
              {label}
              {active && (
                <span className="ml-auto size-1 rounded-full bg-[var(--accent-ui)]" />
              )}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-[#1f1f1f] p-4">
        <div className="rounded-xl border border-[#242424] bg-[#0d0d0d] p-3">
          <div className="flex items-center gap-2.5">
            <span className="grid size-8 shrink-0 place-items-center rounded-full bg-gradient-to-b from-[#3a3a3a] to-[#1c1c1c] text-xs font-medium text-[#d4d4d4]">
              管
            </span>
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-[#ededed]">
                dev-admin
              </p>
              <p className="flex items-center gap-1.5 text-[11px] text-[#666666]">
                <span className="pulse-dot size-1.5 rounded-full bg-[#3fb950]" />
                开发模式会话
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            disabled={signingOut}
            className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg border border-[#2a2a2a] py-1.5 text-xs text-[#a1a1a1] transition-colors duration-150 hover:border-[#f85149]/40 hover:bg-[#f85149]/10 hover:text-[#ffa198] disabled:opacity-60"
          >
            <LogOut className="size-3.5" />
            {signingOut ? "退出中…" : "退出登录"}
          </button>
        </div>
      </div>
    </aside>
  );
}
