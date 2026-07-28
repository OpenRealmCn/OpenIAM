"use client";

import { RotateCcw } from "lucide-react";

import { PageHeader } from "@/components/console/page-header";
import { Reveal } from "@/components/console/reveal";
import { Badge, Separator } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/components/ui/toast";
import { useConsole } from "@/lib/store";
import { cn } from "@/lib/utils";

const accents = [
  { value: "#ffffff", label: "经典白" },
  { value: "#0070f3", label: "Vercel 蓝" },
  { value: "#22d3ee", label: "青" },
  { value: "#34d399", label: "绿" },
  { value: "#f59e0b", label: "琥珀" },
  { value: "#f472b6", label: "品红" },
];

function Section({
  title,
  hint,
  children,
  delay = 0,
}: {
  title: string;
  hint: string;
  children: React.ReactNode;
  delay?: number;
}) {
  return (
    <Reveal delay={delay}>
      <section className="rounded-xl border border-[#222222] bg-[#0d0d0d] p-6">
        <h2 className="font-medium tracking-tight text-[#ededed]">{title}</h2>
        <p className="mt-1 text-sm text-[#8a8a8a]">{hint}</p>
        <div className="mt-6">{children}</div>
      </section>
    </Reveal>
  );
}

export default function SettingsPage() {
  const {
    state,
    setAccent,
    setDensity,
    setSecurity,
    setFlag,
    setSessionTtlHours,
    resetPreview,
  } = useConsole();
  const { toast } = useToast();

  const { settings } = state;

  return (
    <div className="max-w-3xl">
      <PageHeader
        eyebrow="Configuration"
        title="系统设置"
        description="所有更改即时热更新并保存在本地。接入后端配置 API 后将同步到服务端。"
      />

      <div className="space-y-4">
        <Section
          title="外观"
          hint="强调色与界面密度立即应用于整个控制台。"
        >
          <div>
            <p className="text-sm font-medium text-[#d4d4d4]">强调色</p>
            <div className="mt-3 flex flex-wrap gap-3">
              {accents.map((a) => (
                <button
                  key={a.value}
                  type="button"
                  onClick={() => {
                    setAccent(a.value);
                    toast(`强调色已切换为「${a.label}」`, "info");
                  }}
                  className="group flex flex-col items-center gap-2"
                >
                  <span
                    className={cn(
                      "grid size-10 place-items-center rounded-full border-2 transition-transform duration-150 group-hover:scale-110 group-active:scale-95",
                      settings.accent === a.value
                        ? "border-white"
                        : "border-transparent",
                    )}
                    style={{ backgroundColor: a.value }}
                  >
                    {settings.accent === a.value && (
                      <span className="size-2 rounded-full bg-black/70" />
                    )}
                  </span>
                  <span
                    className={cn(
                      "text-[11px] transition-colors",
                      settings.accent === a.value
                        ? "text-white"
                        : "text-[#666666] group-hover:text-[#a1a1a1]",
                    )}
                  >
                    {a.label}
                  </span>
                </button>
              ))}
            </div>
          </div>

          <Separator className="my-6" />

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-[#d4d4d4]">紧凑密度</p>
              <p className="mt-1 text-xs text-[#666666]">
                减小表格行高，在有限空间内展示更多记录。
              </p>
            </div>
            <Switch
              checked={settings.density === "compact"}
              onChange={(v) => {
                setDensity(v ? "compact" : "comfortable");
                toast(v ? "已切换到紧凑密度" : "已切换到舒适密度", "info");
              }}
              label="紧凑密度"
            />
          </div>
        </Section>

        <Section
          title="安全策略"
          hint="策略热更新，立即影响登录与创建用户时的密码校验。"
          delay={80}
        >
          <div className="space-y-7">
            <div>
              <div className="flex items-baseline justify-between">
                <p className="text-sm font-medium text-[#d4d4d4]">
                  密码最小长度
                </p>
                <span className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-xs text-white">
                  {settings.security.passwordMinLength} 位
                </span>
              </div>
              <div className="mt-3">
                <Slider
                  label="密码最小长度"
                  min={8}
                  max={32}
                  value={settings.security.passwordMinLength}
                  onChange={(v) => setSecurity({ passwordMinLength: v })}
                />
              </div>
            </div>

            <div>
              <div className="flex items-baseline justify-between">
                <p className="text-sm font-medium text-[#d4d4d4]">
                  登录失败上限
                </p>
                <span className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-xs text-white">
                  {settings.security.loginAttemptLimit} 次
                </span>
              </div>
              <div className="mt-3">
                <Slider
                  label="登录失败上限"
                  min={3}
                  max={10}
                  value={settings.security.loginAttemptLimit}
                  onChange={(v) => setSecurity({ loginAttemptLimit: v })}
                />
              </div>
            </div>

            <div>
              <div className="flex items-baseline justify-between">
                <p className="text-sm font-medium text-[#d4d4d4]">
                  账号锁定时长
                </p>
                <span className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-xs text-white">
                  {settings.security.lockDurationMinutes} 分钟
                </span>
              </div>
              <div className="mt-3 w-56">
                <Select
                  aria-label="账号锁定时长"
                  value={settings.security.lockDurationMinutes}
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    setSecurity({ lockDurationMinutes: v });
                    toast(`锁定时长已更新为 ${v} 分钟`);
                  }}
                >
                  <option value={5}>5 分钟</option>
                  <option value={15}>15 分钟</option>
                  <option value={30}>30 分钟</option>
                  <option value={60}>60 分钟</option>
                </Select>
              </div>
            </div>
          </div>
        </Section>

        <Section
          title="会话"
          hint="浏览器会话的有效期与 Cookie 名称。"
          delay={160}
        >
          <div className="flex items-baseline justify-between">
            <p className="text-sm font-medium text-[#d4d4d4]">会话有效期</p>
            <span className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-xs text-white">
              {settings.sessionTtlHours} 小时
            </span>
          </div>
          <div className="mt-3">
            <Slider
              label="会话有效期"
              min={1}
              max={24}
              value={settings.sessionTtlHours}
              onChange={setSessionTtlHours}
            />
          </div>

          <div className="mt-6 flex items-center justify-between">
            <p className="text-sm text-[#8a8a8a]">Cookie 名称</p>
            <Badge className="font-mono">openiam_session</Badge>
          </div>
        </Section>

        <Section title="功能开关" hint="预览环境中的特性开关。" delay={240}>
          <div className="space-y-5">
            {[
              {
                key: "enforcePkce" as const,
                label: "强制 PKCE S256",
                desc: "所有授权码流程必须携带 PKCE 校验。",
              },
              {
                key: "auditLogin" as const,
                label: "登录审计",
                desc: "记录全部登录成功与失败事件。",
              },
              {
                key: "mfaPreview" as const,
                label: "多因素认证（预览）",
                desc: "为管理员账号启用 TOTP 二次验证。",
              },
            ].map((flag) => (
              <div
                key={flag.key}
                className="flex items-center justify-between gap-4"
              >
                <div>
                  <p className="text-sm font-medium text-[#d4d4d4]">
                    {flag.label}
                  </p>
                  <p className="mt-1 text-xs text-[#666666]">{flag.desc}</p>
                </div>
                <Switch
                  checked={settings.flags[flag.key]}
                  onChange={(v) => {
                    setFlag(flag.key, v);
                    toast(`${flag.label} ${v ? "已开启" : "已关闭"}`);
                  }}
                  label={flag.label}
                />
              </div>
            ))}
          </div>
        </Section>

        <Reveal delay={320}>
          <section className="rounded-xl border border-[#3a1b1b] bg-[#140b0b] p-6">
            <h2 className="font-medium tracking-tight text-[#ffa198]">
              重置预览数据
            </h2>
            <p className="mt-1 text-sm text-[#8a8a8a]">
              清除本地创建的用户、角色与设置，恢复到初始预览状态。
            </p>
            <div className="mt-5">
              <Button
                variant="outline"
                onClick={() => {
                  resetPreview();
                  toast("预览数据已重置", "info");
                }}
                className="border-[#f85149]/40 text-[#ffa198] hover:border-[#f85149] hover:bg-[#f85149]/10"
              >
                <RotateCcw className="size-4" />
                恢复默认
              </Button>
            </div>
          </section>
        </Reveal>
      </div>
    </div>
  );
}
