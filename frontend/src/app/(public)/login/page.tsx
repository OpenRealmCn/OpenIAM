import type { Metadata } from "next";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { BrandMark } from "@/components/brand-mark";
import { Button } from "@/components/ui/button";

export const metadata: Metadata = {
  title: "登录",
};

const inputClass =
  "mt-2 h-11 w-full rounded-xl border border-[#2e2e2e] bg-[#111111] px-4 text-sm text-white outline-none transition-colors placeholder:text-[#525252] focus:border-[#6b6b6b] disabled:cursor-not-allowed disabled:opacity-60";

export default function LoginPage() {
  return (
    <main className="relative flex min-h-screen flex-col">
      <div className="vercel-glow pointer-events-none absolute inset-0" />

      <header className="relative z-10 flex h-16 items-center justify-between border-b border-[#1f1f1f] px-6">
        <BrandMark />
        <Link
          href="/"
          className="inline-flex items-center gap-1.5 text-sm text-[#a1a1a1] transition-colors hover:text-white"
        >
          <ArrowLeft className="size-4" />
          返回首页
        </Link>
      </header>

      <section className="relative z-10 flex flex-1 items-center justify-center px-6 py-16">
        <div className="w-full max-w-[400px]">
          <div className="rounded-2xl border border-[#242424] bg-[#0d0d0d] p-8 shadow-[0_16px_60px_rgba(0,0,0,0.6)]">
            <h1 className="text-2xl font-semibold tracking-[-0.02em] text-white">
              登录 OpenIAM
            </h1>
            <p className="mt-2 text-sm text-[#8a8a8a]">
              使用你的 OpenRealm 企业身份继续。
            </p>

            <div className="mt-8 space-y-4" aria-describedby="login-status">
              <label className="block text-sm font-medium text-[#d4d4d4]">
                用户名或邮箱
                <input
                  disabled
                  className={inputClass}
                  placeholder="name@openrealm.io"
                />
              </label>
              <label className="block text-sm font-medium text-[#d4d4d4]">
                密码
                <input
                  disabled
                  type="password"
                  className={inputClass}
                  placeholder="••••••••••••"
                />
              </label>
              <Button className="w-full" size="lg" disabled>
                验证身份
              </Button>
            </div>
          </div>

          <p
            id="login-status"
            className="mt-6 rounded-xl border border-[#2e2e2e] bg-[#111111] px-4 py-3 text-center text-xs leading-5 text-[#8a8a8a]"
          >
            登录 API 尚未启用。当前版本仅初始化安全边界，不接受或传输凭据。
          </p>
        </div>
      </section>

      <footer className="relative z-10 border-t border-[#1f1f1f] py-5 text-center text-xs text-[#666666]">
        OpenRealm Private Infrastructure
      </footer>
    </main>
  );
}
