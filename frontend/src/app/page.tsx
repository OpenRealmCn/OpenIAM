import Link from "next/link";
import { ArrowRight, Fingerprint, KeyRound, ShieldCheck } from "lucide-react";

import { BrandMark } from "@/components/brand-mark";
import { Button } from "@/components/ui/button";

const capabilities = [
  {
    icon: Fingerprint,
    label: "统一身份",
    detail: "集中管理 OpenRealm 员工与应用身份。",
  },
  {
    icon: KeyRound,
    label: "标准协议",
    detail: "面向 OAuth 2.1、OIDC 与企业级 SSO。",
  },
  {
    icon: ShieldCheck,
    label: "精细授权",
    detail: "通过可审计 RBAC 控制每一次访问。",
  },
];

export default function HomePage() {
  return (
    <main className="relative min-h-screen overflow-hidden">
      <div className="grid-field pointer-events-none absolute inset-0" />
      <div className="vercel-glow pointer-events-none absolute inset-0" />

      <div className="relative z-10 mx-auto flex min-h-screen max-w-6xl flex-col px-6">
        <header className="flex h-16 items-center justify-between border-b border-[var(--border)]">
          <BrandMark />
          <nav className="flex items-center gap-2">
            <Button asChild variant="ghost" size="sm">
              <a href="http://localhost:8080/health/live">服务状态</a>
            </Button>
            <Button asChild size="sm">
              <Link href="/login">管理控制台</Link>
            </Button>
          </nav>
        </header>

        <section className="flex flex-1 flex-col items-center justify-center py-24 text-center">
          <div className="mb-8 inline-flex items-center gap-2 rounded-full border border-[var(--border-strong)] bg-[var(--surface)] px-4 py-1.5 text-[13px] text-[var(--muted)]">
            <span className="size-1.5 rounded-full bg-[var(--accent)]" />
            OpenRealm Identity Core
          </div>

          <h1 className="max-w-4xl bg-gradient-to-b from-[var(--fg-strong)] to-[var(--muted)] bg-clip-text text-6xl font-semibold leading-[1.05] tracking-[-0.04em] text-transparent sm:text-7xl lg:text-8xl">
            一个入口，
            <br />
            守护每个身份。
          </h1>

          <p className="mt-7 max-w-xl text-balance text-base leading-7 text-[var(--muted)] sm:text-lg">
            OpenIAM 为 OpenRealm
            提供统一登录、标准身份协议和可验证的权限边界，让人员、应用与资源建立清晰可信的连接。
          </p>

          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Button asChild size="lg">
              <Link href="/login">
                进入身份中心
                <ArrowRight className="size-4" />
              </Link>
            </Button>
            <Button asChild size="lg" variant="outline">
              <Link href="/dashboard">查看控制台</Link>
            </Button>
          </div>
        </section>

        <section className="grid gap-4 pb-20 sm:grid-cols-3">
          {capabilities.map(({ icon: Icon, label, detail }) => (
            <article
              key={label}
              className="group rounded-2xl border border-[var(--border)] bg-[var(--surface)] p-6 transition-colors duration-200 hover:border-[var(--border-strong)]"
            >
              <div className="grid size-10 place-items-center rounded-full border border-[var(--border-strong)] bg-[var(--surface-2)] text-[var(--fg)] transition-colors group-hover:border-[var(--faint)]">
                <Icon className="size-4.5" strokeWidth={1.6} />
              </div>
              <h2 className="mt-5 font-medium tracking-tight text-[var(--fg-strong)]">
                {label}
              </h2>
              <p className="mt-2 text-sm leading-6 text-[var(--muted)]">
                {detail}
              </p>
            </article>
          ))}
        </section>

        <footer className="flex min-h-16 flex-wrap items-center justify-between gap-4 border-t border-[var(--border)] py-5 text-xs text-[var(--faint)]">
          <span>OpenRealm Private Infrastructure</span>
          <span>OAuth 2.1 / OIDC / RBAC</span>
        </footer>
      </div>
    </main>
  );
}
