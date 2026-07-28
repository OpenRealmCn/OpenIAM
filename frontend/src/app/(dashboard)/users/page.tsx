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
            <Search className="pointer-events-none absolute left-3.5 top-1/2 size-4 -translate-y-1/2 text-[#666666]" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索用户…"
              className="h-10 w-64 rounded-full border border-[#2e2e2e] bg-[#111111] pl-10 pr-4 text-sm text-white outline-none transition-colors duration-150 placeholder:text-[#525252] focus:border-[var(--accent-ui)]"
            />
          </label>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="size-4" />
            创建用户
          </Button>
        </div>
      </PageHeader>

      <p
        className="animate-rise mb-4 font-mono text-[11px] text-[#666666]"
        style={{ animationDelay: "60ms" }}
      >
        共 {state.users.length} 位用户
        {query.trim() ? ` · 匹配 ${filtered.length} 位` : ""}
      </p>

      <div
        className="animate-rise overflow-x-auto rounded-xl border border-[#222222] bg-[#0d0d0d]"
        style={{ animationDelay: "100ms" }}
      >
        <table className="w-full min-w-[760px] text-sm">
          <thead>
            <tr className="border-b border-[#1f1f1f] text-left font-mono text-[11px] uppercase tracking-[0.16em] text-[#666666]">
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
                    "border-b border-[#161616] transition-colors duration-150 last:border-b-0 hover:bg-white/[0.025]",
                    flashId === u.id && "row-flash",
                  )}
                >
                  <td className={cellPad}>
                    <div className="flex items-center gap-3">
                      <span className="grid size-8 shrink-0 place-items-center rounded-full bg-gradient-to-b from-[#3a3a3a] to-[#1c1c1c] text-xs font-medium text-[#d4d4d4]">
                        {u.name[0]}
                      </span>
                      <div className="min-w-0">
                        <p className="truncate font-medium text-[#ededed]">
                          {u.name}
                        </p>
                        <p className="truncate font-mono text-xs text-[#666666]">
                          {u.email}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className={cn(cellPad, "text-[#a1a1a1]")}>
                    {u.department}
                  </td>
                  <td className={cellPad}>
                    {u.roles.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {u.roles.map((r) => (
                          <span
                            key={r}
                            className="rounded-full border border-[#2a2a2a] bg-[#161616] px-2 py-0.5 font-mono text-[11px] text-[#a1a1a1]"
                          >
                            {r}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-[#525252]">未分配</span>
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
                    className={cn(cellPad, "font-mono text-xs text-[#8a8a8a]")}
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
                  className="px-5 py-12 text-center text-sm text-[#666666]"
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
