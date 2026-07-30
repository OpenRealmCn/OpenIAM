"use client";

import { useState } from "react";
import { Plus, X } from "lucide-react";

import { PageHeader } from "@/components/console/page-header";
import { Reveal } from "@/components/console/reveal";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import { useToast } from "@/components/ui/toast";
import { useConsole } from "@/lib/store";
import { getTheme } from "@/lib/themes";

const PROFILE_KEY = "openiam-profile-v1";

interface Profile {
  displayName: string;
  email: string;
  department: string;
  title: string;
  groups: string[];
}

const defaultProfile: Profile = {
  displayName: "平台管理员",
  email: "admin@openrealm.io",
  department: "平台工程部",
  title: "Identity Platform Lead",
  groups: ["identity-core", "sre-oncall"],
};

function loadProfile(): Profile {
  if (typeof window === "undefined") return defaultProfile;
  try {
    const raw = window.localStorage.getItem(PROFILE_KEY);
    if (!raw) return defaultProfile;
    return { ...defaultProfile, ...(JSON.parse(raw) as Partial<Profile>) };
  } catch {
    return defaultProfile;
  }
}

export default function ProfilePage() {
  const { state } = useConsole();
  const { toast } = useToast();
  const [profile, setProfile] = useState<Profile>(loadProfile);
  const [groupInput, setGroupInput] = useState("");

  function update<K extends keyof Profile>(key: K, value: Profile[K]) {
    setProfile((p) => ({ ...p, [key]: value }));
  }

  function addGroup() {
    const value = groupInput.trim();
    if (!value || profile.groups.includes(value)) {
      setGroupInput("");
      return;
    }
    update("groups", [...profile.groups, value]);
    setGroupInput("");
  }

  function removeGroup(group: string) {
    update(
      "groups",
      profile.groups.filter((g) => g !== group),
    );
  }

  function handleSave() {
    try {
      window.localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
      toast("资料已保存到你的账户");
    } catch {
      toast("保存失败，请重试", "error");
    }
  }

  const theme = getTheme(state.settings.themeId);
  const modeLabel =
    state.settings.themeMode === "auto"
      ? "自动"
      : state.settings.themeMode === "dark"
        ? "黑暗"
        : "明亮";

  return (
    <div className="max-w-3xl">
      <PageHeader
        eyebrow="Account"
        title="我的资料"
        description="管理你的个人信息、身份组与偏好。所有更改保存到你的账户。"
      />

      <div className="space-y-4">
        <Reveal>
          <section className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6">
            <div className="flex items-center gap-4">
              <span className="grid size-16 shrink-0 place-items-center rounded-full bg-[var(--surface-3)] text-2xl font-semibold text-[var(--fg-strong)]">
                {profile.displayName.slice(0, 1)}
              </span>
              <div>
                <h2 className="text-lg font-semibold text-[var(--fg-strong)]">
                  {profile.displayName}
                </h2>
                <p className="font-mono text-sm text-[var(--muted)]">
                  {profile.email}
                </p>
              </div>
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-2">
              <Label>
                显示名称
                <Input
                  className="mt-2"
                  value={profile.displayName}
                  onChange={(e) => update("displayName", e.target.value)}
                />
              </Label>
              <Label>
                邮箱
                <Input
                  className="mt-2"
                  type="email"
                  value={profile.email}
                  onChange={(e) => update("email", e.target.value)}
                />
              </Label>
              <Label>
                部门
                <Input
                  className="mt-2"
                  value={profile.department}
                  onChange={(e) => update("department", e.target.value)}
                />
              </Label>
              <Label>
                职位
                <Input
                  className="mt-2"
                  value={profile.title}
                  onChange={(e) => update("title", e.target.value)}
                />
              </Label>
            </div>
          </section>
        </Reveal>

        <Reveal delay={80}>
          <section className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6">
            <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
              身份组
            </h2>
            <p className="mt-1 text-sm text-[var(--muted)]">
              身份组用于跨系统的批量授权与通知分发，你可以自行加入或退出。
            </p>

            <div className="mt-4 flex flex-wrap gap-2">
              {profile.groups.map((group) => (
                <span
                  key={group}
                  className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border-strong)] bg-[var(--surface-2)] py-1 pl-3 pr-1.5 font-mono text-xs text-[var(--fg)]"
                >
                  {group}
                  <button
                    type="button"
                    onClick={() => removeGroup(group)}
                    aria-label={`移除 ${group}`}
                    className="grid size-4 place-items-center rounded-full text-[var(--faint)] transition-colors hover:bg-red-500/15 hover:text-red-400"
                  >
                    <X className="size-3" />
                  </button>
                </span>
              ))}
              {profile.groups.length === 0 && (
                <span className="text-sm text-[var(--faint)]">
                  尚未加入任何身份组
                </span>
              )}
            </div>

            <div className="mt-4 flex gap-2">
              <Input
                value={groupInput}
                onChange={(e) => setGroupInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    addGroup();
                  }
                }}
                placeholder="输入身份组名称，回车加入"
                className="max-w-xs font-mono"
              />
              <Button variant="outline" onClick={addGroup}>
                <Plus className="size-4" />
                加入
              </Button>
            </div>
          </section>
        </Reveal>

        <Reveal delay={160}>
          <section className="flex items-center justify-between rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6">
            <div>
              <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
                界面偏好
              </h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                当前主题与模式已保存到你的账户。
              </p>
            </div>
            <div className="flex items-center gap-2">
              <Badge>{theme.name}</Badge>
              <Badge>{modeLabel}</Badge>
            </div>
          </section>
        </Reveal>

        <div className="flex justify-end">
          <Button size="lg" onClick={handleSave}>
            保存资料
          </Button>
        </div>
      </div>
    </div>
  );
}
