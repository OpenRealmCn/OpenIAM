"use client";

import {
  auditResultMeta,
  loginTrend,
  moduleStatus,
  previewAuditEvents,
} from "@/lib/preview-data";
import { PageHeader } from "@/components/console/page-header";
import { StatusPill } from "@/components/console/status-pill";
import { useConsole } from "@/lib/store";

const panelClass = "rounded-xl border border-[var(--border)] bg-[var(--surface)]";

export default function DashboardPage() {
  const { state } = useConsole();

  const maxCount = Math.max(...loginTrend.map((d) => d.count));
  const peak = loginTrend.reduce((a, b) => (b.count > a.count ? b : a));
  const activeUsers = state.users.filter((u) => u.status === "active").length;
  const topRoles = [...state.roles]
    .sort((a, b) => b.members - a.members)
    .slice(0, 4);
  const maxMembers = Math.max(...topRoles.map((r) => r.members), 1);

  const stats = [
    { label: "用户总数", value: state.users.length },
    { label: "活跃用户", value: activeUsers },
    { label: "角色", value: state.roles.length },
    { label: "审计事件 / 今日", value: previewAuditEvents.length },
  ];

  return (
    <div>
      <PageHeader
        eyebrow="Overview"
        title="身份控制台"
        description="OpenRealm 身份与访问管理运行总览。创建用户或角色后，统计将实时更新。"
      />

      <div className="grid gap-4 lg:grid-cols-3">
        <section
          className={`${panelClass} animate-rise p-6 lg:col-span-2`}
          style={{ animationDelay: "60ms" }}
        >
          <div className="flex items-baseline justify-between">
            <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
              登录趋势
            </h2>
            <p className="font-mono text-[11px] text-[var(--faint)]">
              近 14 天 · 峰值 {peak.count} 次 / {peak.day}
            </p>
          </div>

          <div className="mt-6 flex h-40 items-end gap-1.5">
            {loginTrend.map((d, i) => (
              <div
                key={d.day}
                className="group relative flex h-full flex-1 items-end"
              >
                <div
                  title={`${d.day} · ${d.count} 次登录`}
                  className="animate-bar w-full rounded-t-[3px] bg-[var(--accent-dim)] transition-colors duration-150 group-hover:bg-[var(--accent)]"
                  style={{
                    height: `${(d.count / maxCount) * 100}%`,
                    animationDelay: `${i * 45}ms`,
                  }}
                />
              </div>
            ))}
          </div>
          <div className="mt-2 flex justify-between font-mono text-[10px] text-[var(--faint)]">
            <span>{loginTrend[0].day}</span>
            <span>{loginTrend[loginTrend.length - 1].day}</span>
          </div>

          <div className="mt-6 grid grid-cols-2 divide-x divide-[var(--border)] border-t border-[var(--border)] sm:grid-cols-4">
            {stats.map((s) => (
              <div key={s.label} className="px-4 pt-4 first:pl-0">
                <p className="text-xs text-[var(--muted)]">{s.label}</p>
                <p className="mt-1 text-2xl font-semibold tracking-tight text-[var(--fg-strong)]">
                  {s.value}
                </p>
              </div>
            ))}
          </div>
        </section>

        <section
          className={`${panelClass} animate-rise p-6`}
          style={{ animationDelay: "120ms" }}
        >
          <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
            模块状态
          </h2>
          <ul className="mt-5 space-y-4">
            {moduleStatus.map((m) => (
              <li key={m.name} className="flex items-center gap-3">
                <span
                  className={
                    m.ready
                      ? "pulse-dot size-1.5 shrink-0 rounded-full bg-emerald-500"
                      : "size-1.5 shrink-0 rounded-full bg-amber-500"
                  }
                />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-[var(--fg)]">{m.label}</p>
                  <p className="truncate font-mono text-[11px] text-[var(--faint)]">
                    {m.name} · {m.note}
                  </p>
                </div>
                <StatusPill
                  tone={m.ready ? "green" : "amber"}
                  label={m.ready ? "已装配" : "开发中"}
                />
              </li>
            ))}
          </ul>
        </section>

        <section
          className={`${panelClass} animate-rise p-6 lg:col-span-2`}
          style={{ animationDelay: "180ms" }}
        >
          <div className="flex items-baseline justify-between">
            <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
              最近活动
            </h2>
            <p className="font-mono text-[11px] text-[var(--faint)]">audit stream</p>
          </div>
          <ul className="mt-4 divide-y divide-[var(--border)]">
            {previewAuditEvents.slice(0, 6).map((e) => (
              <li
                key={`${e.occurredAt}-${e.action}`}
                className="flex items-center gap-4 py-3 transition-colors duration-150 hover:bg-[var(--surface-2)]"
              >
                <span className="w-28 shrink-0 font-mono text-[11px] text-[var(--faint)]">
                  {e.occurredAt}
                </span>
                <span className="min-w-0 flex-1 truncate text-sm text-[var(--fg)]">
                  <span className="font-medium text-[var(--fg-strong)]">
                    {e.actor}
                  </span>
                  <span className="mx-2 font-mono text-xs text-[var(--muted)]">
                    {e.action}
                  </span>
                  <span className="font-mono text-xs text-[var(--faint)]">
                    {e.resource}
                  </span>
                </span>
                <StatusPill
                  tone={auditResultMeta[e.result].tone}
                  label={auditResultMeta[e.result].label}
                />
              </li>
            ))}
          </ul>
        </section>

        <section
          className={`${panelClass} animate-rise p-6`}
          style={{ animationDelay: "240ms" }}
        >
          <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
            角色分布
          </h2>
          <ul className="mt-5 space-y-5">
            {topRoles.map((r) => (
              <li key={r.code}>
                <div className="flex items-baseline justify-between text-sm">
                  <span className="text-[var(--fg)]">{r.name}</span>
                  <span className="font-mono text-[11px] text-[var(--faint)]">
                    {r.members} 人
                  </span>
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[var(--surface-3)]">
                  <div
                    className="h-full rounded-full bg-[var(--accent)] opacity-80 transition-[width] duration-500"
                    style={{ width: `${(r.members / maxMembers) * 100}%` }}
                  />
                </div>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
