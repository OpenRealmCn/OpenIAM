"use client";

import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { FieldHint, Input, Label } from "@/components/ui/input";
import { useConsole } from "@/lib/store";
import { useToast } from "@/components/ui/toast";
import { cn } from "@/lib/utils";

export function CreateUserDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  const { state, addUser } = useConsole();
  const { toast } = useToast();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [department, setDepartment] = useState("");
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState<string[]>([]);

  const minLength = state.settings.security.passwordMinLength;

  const strength = useMemo(() => {
    let score = 0;
    if (password.length >= minLength) score += 1;
    if (password.length >= minLength + 4) score += 1;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score += 1;
    if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score += 1;
    return Math.min(score, 4);
  }, [password, minLength]);

  const strengthLabel = ["过短", "较弱", "一般", "良好", "强"][strength];

  function toggleRole(code: string) {
    setRoles((prev) =>
      prev.includes(code) ? prev.filter((r) => r !== code) : [...prev, code],
    );
  }

  const passwordOk = password.length >= minLength;
  const canSubmit =
    username.trim() !== "" && email.includes("@") && passwordOk;

  function handleSubmit() {
    if (!canSubmit) return;
    const user = addUser({ username, email, displayName, department, roles });
    toast(`已创建用户 ${user.name}`);
    onCreated(user.id);
    onClose();
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title="创建用户"
      description="新成员将立即获得所选角色对应的访问权限。"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit}>
            创建用户
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Label>
            用户名 *
            <Input
              className="mt-2"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="jane.doe"
              autoFocus
            />
          </Label>
          <Label>
            邮箱 *
            <Input
              className="mt-2"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="jane@openrealm.io"
            />
          </Label>
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Label>
            显示名称
            <Input
              className="mt-2"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Jane Doe"
            />
          </Label>
          <Label>
            部门
            <Input
              className="mt-2"
              value={department}
              onChange={(e) => setDepartment(e.target.value)}
              placeholder="平台工程部"
            />
          </Label>
        </div>

        <div>
          <Label>
            初始密码 *
            <Input
              className="mt-2"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={`至少 ${minLength} 位`}
            />
          </Label>
          {password && (
            <div className="mt-2.5">
              <div className="flex gap-1.5">
                {[0, 1, 2, 3].map((i) => (
                  <span
                    key={i}
                    className={cn(
                      "h-1 flex-1 rounded-full transition-colors duration-300",
                      i < strength
                        ? "bg-[var(--accent-ui)]"
                        : "bg-[#2a2a2a]",
                    )}
                  />
                ))}
              </div>
              <FieldHint>
                密码强度：{strengthLabel} · 当前策略要求至少 {minLength} 位
              </FieldHint>
            </div>
          )}
        </div>

        <div>
          <p className="text-sm font-medium text-[#d4d4d4]">分配角色</p>
          <div className="mt-2.5 flex flex-wrap gap-2">
            {state.roles.map((role) => {
              const active = roles.includes(role.code);
              return (
                <button
                  key={role.code}
                  type="button"
                  onClick={() => toggleRole(role.code)}
                  className={cn(
                    "rounded-full border px-3 py-1.5 font-mono text-xs transition-all duration-150 active:scale-95",
                    active
                      ? "border-[var(--accent-ui)] bg-[var(--accent-ui-dim)] text-white"
                      : "border-[#2a2a2a] bg-[#111111] text-[#8a8a8a] hover:border-[#4a4a4a] hover:text-white",
                  )}
                >
                  {role.code}
                </button>
              );
            })}
          </div>
          <FieldHint>已选择 {roles.length} 个角色</FieldHint>
        </div>
      </div>
    </Dialog>
  );
}
