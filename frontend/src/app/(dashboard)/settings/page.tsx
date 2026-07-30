"use client";

import { useEffect, useState } from "react";
import { Monitor, Moon, RotateCcw, Sun } from "lucide-react";

import { PageHeader } from "@/components/console/page-header";
import { Reveal } from "@/components/console/reveal";
import { Badge, Separator } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/components/ui/toast";
import { useConsole } from "@/lib/store";
import {
  CUSTOM_THEME_ID,
  themes,
  type ThemeMode,
  type ThemeTokens,
} from "@/lib/themes";
import { cn } from "@/lib/utils";

function useSystemDark() {
  const [dark, setDark] = useState(
    () =>
      typeof window !== "undefined" &&
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches,
  );
  useEffect(() => {
    if (typeof window === "undefined" || !window.matchMedia) return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const fn = (e: MediaQueryListEvent) => setDark(e.matches);
    mq.addEventListener("change", fn);
    return () => mq.removeEventListener("change", fn);
  }, []);
  return dark;
}

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
      <section className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6">
        <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
          {title}
        </h2>
        <p className="mt-1 text-sm text-[var(--muted)]">{hint}</p>
        <div className="mt-6">{children}</div>
      </section>
    </Reveal>
  );
}

const modeOptions: { value: ThemeMode; label: string; icon: typeof Sun }[] = [
  { value: "light", label: "明亮", icon: Sun },
  { value: "dark", label: "黑暗", icon: Moon },
  { value: "auto", label: "自动", icon: Monitor },
];

const customFields: { key: keyof ThemeTokens; label: string }[] = [
  { key: "accent", label: "强调色" },
  { key: "bg", label: "背景" },
  { key: "surface", label: "面板" },
  { key: "fg", label: "文字" },
  { key: "border", label: "边框" },
];

export default function SettingsPage() {
  const {
    state,
    setThemeMode,
    setThemeId,
    setCustomTokens,
    setDensity,
    setSecurity,
    setFlag,
    setSessionTtlHours,
    setFeishu,
    resetPreview,
  } = useConsole();
  const { toast } = useToast();
  const systemDark = useSystemDark();

  const { settings } = state;
  const effectiveMode: "light" | "dark" =
    settings.themeMode === "auto"
      ? systemDark
        ? "dark"
        : "light"
      : settings.themeMode;

  const customTokens = settings.customTheme[effectiveMode];

  return (
    <div className="max-w-4xl">
      <PageHeader
        eyebrow="Configuration"
        title="系统设置"
        description="主题、外观与策略即时热更新，并保存在你的账户中。接入后端后将同步到服务端。"
      />

      <div className="space-y-4">
        <Section
          title="主题模式"
          hint="选择应用程序的整体明暗主题。"
        >
          <div className="grid grid-cols-3 gap-3 sm:max-w-md">
            {modeOptions.map(({ value, label, icon: Icon }) => {
              const active = settings.themeMode === value;
              return (
                <button
                  key={value}
                  type="button"
                  onClick={() => {
                    setThemeMode(value);
                    toast(`主题模式：${label}`);
                  }}
                  className={cn(
                    "flex flex-col items-center gap-2 rounded-xl border p-4 transition-all duration-150 active:scale-[0.98]",
                    active
                      ? "border-[var(--accent)] bg-[var(--accent-dim)]"
                      : "border-[var(--border)] bg-[var(--surface-2)] hover:border-[var(--border-strong)]",
                  )}
                >
                  <Icon
                    className={cn(
                      "size-5",
                      active ? "text-[var(--fg-strong)]" : "text-[var(--muted)]",
                    )}
                  />
                  <span
                    className={cn(
                      "text-sm",
                      active ? "font-medium text-[var(--fg-strong)]" : "text-[var(--muted)]",
                    )}
                  >
                    {label}
                  </span>
                </button>
              );
            })}
          </div>
        </Section>

        <Section
          title="界面外观"
          hint="选择界面的配色方案和视觉风格，或创建自定义主题。更改立即生效并保存到你的账户。"
          delay={60}
        >
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
            {themes.map((t) => {
              const active = settings.themeId === t.id;
              const preview = t[effectiveMode];
              return (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => {
                    setThemeId(t.id);
                    toast(`已应用主题「${t.name}」`);
                  }}
                  className={cn(
                    "group rounded-xl border p-3 text-left transition-all duration-150 hover:-translate-y-0.5 active:scale-[0.98]",
                    active
                      ? "border-[var(--accent)] bg-[var(--accent-dim)]"
                      : "border-[var(--border)] bg-[var(--surface-2)] hover:border-[var(--border-strong)]",
                  )}
                >
                  <span
                    className="relative block h-14 w-full overflow-hidden rounded-lg border border-black/10"
                    style={{ backgroundColor: preview.bg }}
                  >
                    <span
                      className="absolute left-2 top-2 h-2 w-10 rounded-full"
                      style={{ backgroundColor: preview.surface3 }}
                    />
                    <span
                      className="absolute bottom-2 left-2 size-3 rounded-full"
                      style={{ backgroundColor: preview.accent }}
                    />
                    <span
                      className="absolute bottom-2.5 left-7 h-1.5 w-12 rounded-full"
                      style={{ backgroundColor: preview.muted }}
                    />
                  </span>
                  <span
                    className={cn(
                      "mt-2 block truncate text-xs",
                      active
                        ? "font-medium text-[var(--fg-strong)]"
                        : "text-[var(--muted)] group-hover:text-[var(--fg)]",
                    )}
                  >
                    {t.name}
                  </span>
                </button>
              );
            })}

            <button
              type="button"
              onClick={() => {
                setThemeId(CUSTOM_THEME_ID);
                toast("已切换到自定义主题");
              }}
              className={cn(
                "group flex flex-col items-center justify-center gap-1 rounded-xl border border-dashed p-3 transition-all duration-150 hover:-translate-y-0.5 active:scale-[0.98]",
                settings.themeId === CUSTOM_THEME_ID
                  ? "border-[var(--accent)] bg-[var(--accent-dim)]"
                  : "border-[var(--border-strong)] bg-[var(--surface-2)] hover:border-[var(--faint)]",
              )}
            >
              <span className="grid size-8 place-items-center rounded-full border border-[var(--border-strong)] text-lg text-[var(--muted)]">
                +
              </span>
              <span className="text-xs text-[var(--muted)] group-hover:text-[var(--fg)]">
                自定义
              </span>
            </button>
          </div>

          {settings.themeId === CUSTOM_THEME_ID && (
            <div className="mt-6 rounded-xl border border-[var(--border)] bg-[var(--surface-2)] p-5">
              <div className="flex items-baseline justify-between">
                <p className="text-sm font-medium text-[var(--fg)]">
                  自定义调色（{effectiveMode === "dark" ? "暗色" : "亮色"}）
                </p>
                <span className="font-mono text-[11px] text-[var(--faint)]">
                  随主题模式自动切换
                </span>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-5">
                {customFields.map(({ key, label }) => (
                  <label key={key} className="block">
                    <span className="text-xs text-[var(--muted)]">{label}</span>
                    <input
                      type="color"
                      value={customTokens[key] ?? ""}
                      onChange={(e) =>
                        setCustomTokens(effectiveMode, {
                          [key]: e.target.value,
                        })
                      }
                      className="mt-2 h-10 w-full cursor-pointer rounded-lg border border-[var(--border-strong)] bg-transparent p-1"
                      aria-label={label}
                    />
                  </label>
                ))}
              </div>
            </div>
          )}
        </Section>

        <Section
          title="飞书登录"
          hint="由超级管理员配置。开启后，登录页将展示「使用飞书登录」入口。"
          delay={120}
        >
          <div className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm font-medium text-[var(--fg)]">启用飞书 OAuth</p>
              <p className="mt-1 text-xs text-[var(--faint)]">
                需要先在飞书开放平台创建应用并获取 App ID。
              </p>
            </div>
            <Switch
              checked={settings.feishu.enabled}
              onChange={(v) => {
                setFeishu({ enabled: v });
                toast(v ? "飞书登录已开启" : "飞书登录已关闭");
              }}
              label="启用飞书登录"
            />
          </div>

          {settings.feishu.enabled && (
            <div className="mt-5 grid gap-4 sm:grid-cols-2">
              <Label>
                App ID
                <Input
                  className="mt-2 font-mono"
                  value={settings.feishu.appId}
                  onChange={(e) => setFeishu({ appId: e.target.value })}
                  placeholder="cli_xxxxxxxx"
                />
              </Label>
              <Label>
                回调地址
                <Input
                  className="mt-2 font-mono"
                  value={settings.feishu.redirectUri}
                  onChange={(e) => setFeishu({ redirectUri: e.target.value })}
                />
              </Label>
            </div>
          )}
        </Section>

        <Section
          title="安全策略"
          hint="策略热更新，立即影响登录与创建用户时的密码校验。"
          delay={180}
        >
          <div className="space-y-7">
            <div>
              <div className="flex items-baseline justify-between">
                <p className="text-sm font-medium text-[var(--fg)]">密码最小长度</p>
                <Badge className="font-mono">
                  {settings.security.passwordMinLength} 位
                </Badge>
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
                <p className="text-sm font-medium text-[var(--fg)]">登录失败上限</p>
                <Badge className="font-mono">
                  {settings.security.loginAttemptLimit} 次
                </Badge>
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
                <p className="text-sm font-medium text-[var(--fg)]">账号锁定时长</p>
                <Badge className="font-mono">
                  {settings.security.lockDurationMinutes} 分钟
                </Badge>
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

        <Section title="会话与外观密度" hint="会话有效期与表格密度。" delay={240}>
          <div className="flex items-baseline justify-between">
            <p className="text-sm font-medium text-[var(--fg)]">会话有效期</p>
            <Badge className="font-mono">{settings.sessionTtlHours} 小时</Badge>
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

          <Separator className="my-6" />

          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-[var(--fg)]">紧凑密度</p>
              <p className="mt-1 text-xs text-[var(--faint)]">
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

        <Section title="功能开关" hint="预览环境中的特性开关。" delay={300}>
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
              <div key={flag.key} className="flex items-center justify-between gap-4">
                <div>
                  <p className="text-sm font-medium text-[var(--fg)]">{flag.label}</p>
                  <p className="mt-1 text-xs text-[var(--faint)]">{flag.desc}</p>
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

        <Reveal delay={360}>
          <section className="rounded-xl border border-red-500/30 bg-red-500/5 p-6">
            <h2 className="font-medium tracking-tight text-red-400">重置预览数据</h2>
            <p className="mt-1 text-sm text-[var(--muted)]">
              清除本地创建的用户、角色、主题与设置，恢复到初始预览状态。
            </p>
            <div className="mt-5">
              <Button
                variant="danger"
                onClick={() => {
                  resetPreview();
                  toast("预览数据已重置", "info");
                }}
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
