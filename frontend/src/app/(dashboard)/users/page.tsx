"use client";

import { useMemo, useState } from "react";
import { Plus, Search } from "lucide-react";

import { CreateUserDialog } from "@/components/console/create-user-dialog";
import { PageHeader } from "@/components/console/page-header";
import { StatusPill } from "@/components/console/status-pill";
import { Button } from "@/components/ui/button";
import { userStatusMeta } from "@/lib/preview-data";
import { useConsole } from "@/lib/store";
import { cn } from "@/lib/utils";

export default function UsersPage() {
  const { state } = useConsole();
  const [query, setQuery] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [flashId, setFlashId] = useState<string | null>(null);

  const density = state.settings.density;
  const cellPad = density === "compact" ? "px-5 py-2" : "px-5 py-3.5";

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return state.users;
    return state.users.filter((u) =>
      [u.name, u.email, u.department, u.id, ...u.roles].some((v) =>
        v.toLowerCase().includes(q),
      ),
    );
  }, [query, state.users]);

  function handleCreated(id: string) {
    setFlashId(id);
    window.setTimeout(() => setFlashId(null), 1700);
  }

  return (
    <div>
      <PageHeader
        eyebrow="Directory"
        title="用户"
        description="组织内全部身份的统一视图，支持按姓名、邮箱、部门或角色筛选。"
      >
        <div className="flex items-center gap-3">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-[var(--faint)]" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索用户…"
              className="h-10 w-64 rounded-full border border-[var(--border-strong)] bg-[var(--surface-2)] pl-10 pr-4 text-sm text-[var(--fg)] outline-none transition-colors duration-150 placeholder:text-[var(--faint)] focus:border-[var(--accent)]"
            />
          </label>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="size-4" />
            创建用户
          </Button>
        </div>
      </PageHeader>

      <p
        className="animate-rise mb-4 font-mono text-[11px] text-[var(--faint)]"
        style={{ animationDelay: "60ms" }}
      >
        共 {state.users.length} 位用户
        {query.trim() ? ` · 匹配 ${filtered.length} 位` : ""}
      </p>

      <div
        className="animate-rise overflow-x-auto rounded-xl border border-[var(--border)] bg-[var(--surface)]"
        style={{ animationDelay: "100ms" }}
      >
        <table className="w-full min-w-[760px] text-sm">
          <thead>
            <tr className="border-b border-[var(--border)] text-left font-mono text-[11px] uppercase tracking-[0.16em] text-[var(--faint)]">
              <th className="px-5 py-3.5 font-medium">用户</th>
              <th className="px-5 py-3.5 font-medium">部门</th>
              <th className="px-5 py-3.5 font-medium">角色</th>
              <th className="px-5 py-3.5 font-medium">状态</th>
              <th className="px-5 py-3.5 font-medium">最近登录</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((u) => {
              const meta = userStatusMeta[u.status];
              return (
                <tr
                  key={u.id}
                  className={cn(
                    "border-b border-[var(--border)] transition-colors duration-150 last:border-b-0 hover:bg-[var(--surface-2)]",
                    flashId === u.id && "row-flash",
                  )}
                >
                  <td className={cellPad}>
                    <div className="flex items-center gap-3">
                      <span className="grid size-8 shrink-0 place-items-center rounded-full bg-[var(--surface-3)] text-xs font-medium text-[var(--fg)]">
                        {u.name[0]}
                      </span>
                      <div className="min-w-0">
                        <p className="truncate font-medium text-[var(--fg-strong)]">
                          {u.name}
                        </p>
                        <p className="truncate font-mono text-xs text-[var(--faint)]">
                          {u.email}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className={cn(cellPad, "text-[var(--muted)]")}>
                    {u.department}
                  </td>
                  <td className={cellPad}>
                    {u.roles.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {u.roles.map((r) => (
                          <span
                            key={r}
                            className="rounded-full border border-[var(--border-strong)] bg-[var(--surface-2)] px-2 py-0.5 font-mono text-[11px] text-[var(--muted)]"
                          >
                            {r}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-[var(--faint)]">未分配</span>
                    )}
                  </td>
                  <td className={cellPad}>
                    <StatusPill
                      tone={meta.tone}
                      label={meta.label}
                      pulse={meta.pulse}
                    />
                  </td>
                  <td
                    className={cn(cellPad, "font-mono text-xs text-[var(--muted)]")}
                  >
                    {u.lastLogin}
                  </td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td
                  colSpan={5}
                  className="px-5 py-12 text-center text-sm text-[var(--faint)]"
                >
                  没有匹配 “{query}” 的用户
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {createOpen && (
        <CreateUserDialog
          onClose={() => setCreateOpen(false)}
          onCreated={handleCreated}
        />
      )}
    </div>
  );
}
