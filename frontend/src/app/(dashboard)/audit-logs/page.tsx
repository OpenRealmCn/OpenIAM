"use client";

import { useState } from "react";

import { PageHeader } from "@/components/console/page-header";
import { StatusPill } from "@/components/console/status-pill";
import {
  auditResultMeta,
  previewAuditEvents,
  type AuditResult,
} from "@/lib/preview-data";
import { cn } from "@/lib/utils";

type Filter = "all" | AuditResult;

const filters: { value: Filter; label: string }[] = [
  { value: "all", label: "全部" },
  { value: "success", label: "成功" },
  { value: "failure", label: "失败" },
];

export default function AuditLogsPage() {
  const [filter, setFilter] = useState<Filter>("all");

  const events =
    filter === "all"
      ? previewAuditEvents
      : previewAuditEvents.filter((e) => e.result === filter);

  return (
    <div>
      <PageHeader
        eyebrow="Compliance"
        title="审计日志"
        description="登录、授权、角色变更与客户端操作的安全事件流，全部事件携带请求 ID。"
      >
        <div className="flex items-center gap-1 rounded-full border border-[var(--border-strong)] bg-[var(--surface-2)] p-1">
          {filters.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => setFilter(f.value)}
              className={cn(
                "rounded-full px-3.5 py-1 text-xs font-medium transition-colors duration-150",
                filter === f.value
                  ? "bg-[var(--accent)] text-[var(--accent-fg)]"
                  : "text-[var(--muted)] hover:text-[var(--fg)]",
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </PageHeader>

      <p
        className="animate-rise mb-4 font-mono text-[11px] text-[var(--faint)]"
        style={{ animationDelay: "60ms" }}
      >
        {events.length} 条事件
      </p>

      <div
        className="animate-rise overflow-x-auto rounded-xl border border-[var(--border)] bg-[var(--surface)]"
        style={{ animationDelay: "100ms" }}
      >
        <table className="w-full min-w-[820px] text-sm">
          <thead>
            <tr className="border-b border-[var(--border)] text-left font-mono text-[11px] uppercase tracking-[0.16em] text-[var(--faint)]">
              <th className="px-5 py-3.5 font-medium">时间</th>
              <th className="px-5 py-3.5 font-medium">事件</th>
              <th className="px-5 py-3.5 font-medium">操作者</th>
              <th className="px-5 py-3.5 font-medium">资源</th>
              <th className="px-5 py-3.5 font-medium">来源 IP</th>
              <th className="px-5 py-3.5 font-medium">结果</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e) => (
              <tr
                key={`${e.occurredAt}-${e.action}`}
                className="border-b border-[var(--border)] transition-colors duration-150 last:border-b-0 hover:bg-[var(--surface-2)]"
              >
                <td className="whitespace-nowrap px-5 py-3.5 font-mono text-xs text-[var(--muted)]">
                  {e.occurredAt}
                </td>
                <td className="px-5 py-3.5 font-mono text-xs text-[var(--fg)]">
                  {e.action}
                </td>
                <td className="px-5 py-3.5 text-[var(--muted)]">{e.actor}</td>
                <td className="px-5 py-3.5 font-mono text-xs text-[var(--faint)]">
                  {e.resource}
                </td>
                <td className="px-5 py-3.5 font-mono text-xs text-[var(--faint)]">
                  {e.ip}
                </td>
                <td className="px-5 py-3.5">
                  <StatusPill
                    tone={auditResultMeta[e.result].tone}
                    label={auditResultMeta[e.result].label}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
