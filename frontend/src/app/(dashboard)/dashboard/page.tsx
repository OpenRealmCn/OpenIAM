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

const panelClass = "rounded-xl border border-[#222222] bg-[#0d0d0d]";

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
            <h2 className="font-medium tracking-tight text-[#ededed]">
              登录趋势
            </h2>
            <p className="font-mono text-[11px] text-[#666666]">
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
                  className="animate-bar w-full rounded-t-[3px] bg-[var(--accent-ui-dim)] transition-colors duration-150 group-hover:bg-[var(--accent-ui)]"
                  style={{
                    height: `${(d.count / maxCount) * 100}%`,
                    animationDelay: `${i * 45}ms`,
                  }}
                />
              </div>
            ))}
          </div>
          <div className="mt-2 flex justify-between font-mono text-[10px] text-[#525252]">
            <span>{loginTrend[0].day}</span>
            <span>{loginTrend[loginTrend.length - 1].day}</span>
          </div>

          <div className="mt-6 grid grid-cols-2 divide-x divide-[#1f1f1f] border-t border-[#1f1f1f] sm:grid-cols-4">
            {stats.map((s) => (
              <div key={s.label} className="px-4 pt-4 first:pl-0">
                <p className="text-xs text-[#8a8a8a]">{s.label}</p>
                <p className="mt-1 text-2xl font-semibold tracking-tight text-white">
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
          <h2 className="font-medium tracking-tight text-[#ededed]">
            模块状态
          </h2>
          <ul className="mt-5 space-y-4">
            {moduleStatus.map((m) => (
              <li key={m.name} className="flex items-center gap-3">
                <span
                  className={
                    m.ready
                      ? "pulse-dot size-1.5 shrink-0 rounded-full bg-[#3fb950]"
                      : "size-1.5 shrink-0 rounded-full bg-[#d29922]"
                  }
                />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-[#ededed]">{m.label}</p>
                  <p className="truncate font-mono text-[11px] text-[#666666]">
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
            <h2 className="font-medium tracking-tight text-[#ededed]">
              最近活动
            </h2>
            <p className="font-mono text-[11px] text-[#666666]">audit stream</p>
          </div>
          <ul className="mt-4 divide-y divide-[#181818]">
            {previewAuditEvents.slice(0, 6).map((e) => (
              <li
                key={`${e.occurredAt}-${e.action}`}
                className="flex items-center gap-4 py-3 transition-colors duration-150 hover:bg-white/[0.02]"
              >
                <span className="w-28 shrink-0 font-mono text-[11px] text-[#666666]">
                  {e.occurredAt}
                </span>
                <span className="min-w-0 flex-1 truncate text-sm text-[#d4d4d4]">
                  <span className="font-medium text-white">{e.actor}</span>
                  <span className="mx-2 font-mono text-xs text-[#8a8a8a]">
                    {e.action}
                  </span>
                  <span className="font-mono text-xs text-[#666666]">
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
          <h2 className="font-medium tracking-tight text-[#ededed]">
            角色分布
          </h2>
          <ul className="mt-5 space-y-5">
            {topRoles.map((r) => (
              <li key={r.code}>
                <div className="flex items-baseline justify-between text-sm">
                  <span className="text-[#d4d4d4]">{r.name}</span>
                  <span className="font-mono text-[11px] text-[#666666]">
                    {r.members} 人
                  </span>
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-[#1f1f1f]">
                  <div
                    className="h-full rounded-full bg-[var(--accent-ui)] opacity-80 transition-[width] duration-500"
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
