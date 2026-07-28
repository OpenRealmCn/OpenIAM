"use client";

import { useState, type FormEvent } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";

import { BrandMark } from "@/components/brand-mark";
import { Button } from "@/components/ui/button";

const isDev = process.env.NODE_ENV === "development";
const apiBaseUrl =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

const inputClass =
  "mt-2 h-11 w-full rounded-lg border border-[#2e2e2e] bg-[#111111] px-4 text-sm text-white outline-none transition-colors duration-150 placeholder:text-[#525252] focus:border-[#6b6b6b] disabled:cursor-not-allowed disabled:opacity-60";

const errorMessages: Record<string, string> = {
  missing_params: "飞书登录缺少必要参数，请重试。",
  invalid_state: "飞书登录状态已失效，请重新发起登录。",
  exchange_failed: "飞书授权失败，请重试或联系管理员。",
  no_email: "该飞书账号未绑定邮箱，无法完成登录。",
  provision_failed: "账号开通失败，请联系管理员。",
  session_failed: "会话创建失败，请重试。",
};

function FeishuIcon() {
  return (
    <svg viewBox="0 0 24 24" className="size-4" aria-hidden="true">
      <path
        fill="currentColor"
        d="M13.6 3.4c3.9 1.1 8 4.6 8.4 8.9.3 3-1.4 5.4-4.1 6.3-.4-2.5-2-5.2-4.7-7.4-2.3-1.9-4.9-3.1-7.2-3.4 1.6-2.6 4.5-4.5 7.6-4.4Z"
      />
      <path
        fill="currentColor"
        opacity="0.55"
        d="M4.5 9.9c2.6.1 5.7 1.4 8.3 3.6 2.6 2.2 4.2 4.9 4.4 7.3-1.1.3-2.3.4-3.5.2-4.3-.7-8.3-4.4-9.4-8.4-.3-1-.3-1.9-.2-2.7h.4Z"
      />
    </svg>
  );
}

export function LoginForm({
  returnTo,
  error,
}: {
  returnTo?: string;
  error?: string;
}) {
  const router = useRouter();
  const [submitting, setSubmitting] = useState(false);

  const target =
    returnTo && returnTo.startsWith("/") && !returnTo.startsWith("//")
      ? returnTo
      : "/dashboard";

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!isDev || submitting) return;
    setSubmitting(true);
    const response = await fetch("/api/dev/session", { method: "POST" });
    if (response.ok) {
      router.push(target);
      router.refresh();
      return;
    }
    setSubmitting(false);
  }

  return (
    <main className="relative flex min-h-screen flex-col">
      <div className="vercel-glow pointer-events-none absolute inset-0" />

      <header className="relative z-10 flex h-16 items-center justify-between border-b border-[#1f1f1f] px-6">
        <BrandMark />
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-sm text-[#a1a1a1] transition-colors duration-150 hover:text-white"
        >
          <ArrowLeft className="size-4" />
          返回首页
        </Link>
      </header>

      <section className="relative z-10 flex flex-1 items-center justify-center px-6 py-16">
        <form
          onSubmit={handleSubmit}
          className="animate-rise w-full max-w-[400px]"
        >
          <div className="rounded-2xl border border-[#242424] bg-[#0d0d0d] p-8 shadow-[0_16px_60px_rgba(0,0,0,0.6)]">
            <h1 className="text-2xl font-semibold tracking-[-0.02em] text-white">
              登录 OpenIAM
            </h1>
            <p className="mt-2 text-sm text-[#8a8a8a]">
              使用你的 OpenRealm 企业身份继续。
            </p>

            <div className="mt-8 space-y-4">
              <label className="block text-sm font-medium text-[#d4d4d4]">
                用户名或邮箱
                <input
                  disabled={!isDev || submitting}
                  className={inputClass}
                  placeholder="name@openrealm.io"
                  autoComplete="username"
                />
              </label>
              <label className="block text-sm font-medium text-[#d4d4d4]">
                密码
                <input
                  disabled={!isDev || submitting}
                  type="password"
                  className={inputClass}
                  placeholder="••••••••••••"
                  autoComplete="current-password"
                />
              </label>
              <Button
                type="submit"
                className="w-full"
                size="lg"
                disabled={!isDev || submitting}
              >
                {submitting ? "验证中…" : "验证身份"}
              </Button>
            </div>

            <div className="my-6 flex items-center gap-3">
              <span className="h-px flex-1 bg-[#242424]" />
              <span className="text-[11px] uppercase tracking-[0.18em] text-[#525252]">
                或
              </span>
              <span className="h-px flex-1 bg-[#242424]" />
            </div>

            <a
              href={`${apiBaseUrl}/api/v1/auth/feishu`}
              className="flex h-12 w-full items-center justify-center gap-2.5 rounded-full border border-[#333333] bg-transparent text-sm font-medium text-[#ededed] transition-all duration-150 hover:border-[#525252] hover:bg-white/5 active:scale-[0.98]"
            >
              <FeishuIcon />
              使用飞书登录
            </a>
          </div>

          {error && errorMessages[error] && (
            <p className="mt-6 rounded-xl border border-[#3a1b1b] bg-[#140b0b] px-4 py-3 text-center text-xs leading-5 text-[#ffa198]">
              {errorMessages[error]}
            </p>
          )}

          {isDev ? (
            <p className="mt-6 rounded-xl border border-[#2e2e2e] bg-[#111111] px-4 py-3 text-center text-xs leading-5 text-[#8a8a8a]">
              开发模式：任意凭据均可进入预览，会话仅写入本地浏览器 Cookie，
              生产构建中此入口不可用。
            </p>
          ) : (
            <p className="mt-6 rounded-xl border border-[#2e2e2e] bg-[#111111] px-4 py-3 text-center text-xs leading-5 text-[#8a8a8a]">
              登录 API 尚未启用。当前版本仅初始化安全边界，不接受或传输凭据。
            </p>
          )}
        </form>
      </section>

      <footer className="relative z-10 border-t border-[#1f1f1f] py-5 text-center text-xs text-[#666666]">
        OpenRealm Private Infrastructure
      </footer>
    </main>
  );
}
