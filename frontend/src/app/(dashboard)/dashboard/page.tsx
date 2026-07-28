import { Activity, KeyRound, ShieldCheck, Users } from "lucide-react";

import { BrandMark } from "@/components/brand-mark";

const metrics = [
  { label: "用户", value: "--", icon: Users },
  { label: "角色", value: "--", icon: ShieldCheck },
  { label: "OAuth 客户端", value: "--", icon: KeyRound },
  { label: "活跃会话", value: "--", icon: Activity },
];

export default function DashboardPage() {
  return (
    <main className="min-h-screen">
      <div className="mx-auto max-w-6xl px-6">
        <header className="flex h-16 items-center justify-between border-b border-[#1f1f1f]">
          <BrandMark />
          <span className="rounded-full border border-[#2e2e2e] bg-[#111111] px-3 py-1 text-xs text-[#a1a1a1]">
            Control plane
          </span>
        </header>

        <section className="py-10">
          <h1 className="text-3xl font-semibold tracking-[-0.02em] text-white">
            身份控制台
          </h1>
          <p className="mt-2 text-sm text-[#8a8a8a]">
            OpenRealm 身份与访问管理总览。
          </p>

          <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {metrics.map(({ label, value, icon: Icon }) => (
              <article
                key={label}
                className="rounded-2xl border border-[#222222] bg-[#0d0d0d] p-5 transition-colors duration-200 hover:border-[#3d3d3d]"
              >
                <div className="flex items-center justify-between text-[#8a8a8a]">
                  <span className="text-sm">{label}</span>
                  <span className="grid size-8 place-items-center rounded-full border border-[#2a2a2a] bg-[#161616]">
                    <Icon className="size-3.5" strokeWidth={1.7} />
                  </span>
                </div>
                <p className="mt-8 text-3xl font-semibold tracking-tight text-white">
                  {value}
                </p>
              </article>
            ))}
          </div>

          <p className="mt-8 text-sm text-[#666666]">
            数据 API 将在身份与 RBAC 模块实现后接入。
          </p>
        </section>
      </div>
    </main>
  );
}
