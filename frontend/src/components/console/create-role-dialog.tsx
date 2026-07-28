"use client";

import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { FieldHint, Input, Label } from "@/components/ui/input";
import { useConsole } from "@/lib/store";
import { useToast } from "@/components/ui/toast";
import { previewPermissions } from "@/lib/preview-data";
import { cn } from "@/lib/utils";

export function CreateRoleDialog({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (code: string) => void;
}) {
  const { addRole } = useConsole();
  const { toast } = useToast();

  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [permissions, setPermissions] = useState<string[]>([]);

  const resources = useMemo(
    () => [...new Set(previewPermissions.map((p) => p.resource))],
    [],
  );

  function togglePermission(value: string) {
    setPermissions((prev) =>
      prev.includes(value)
        ? prev.filter((p) => p !== value)
        : [...prev, value],
    );
  }

  const canSubmit = code.trim() !== "" && name.trim() !== "";

  function handleSubmit() {
    if (!canSubmit) return;
    const role = addRole({ code, name, description, permissions });
    toast(`已创建角色 ${role.name}`);
    onCreated(role.code);
    onClose();
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title="创建角色"
      description="角色是权限的集合，创建后可分配给用户。"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit}>
            创建角色
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Label>
            角色代码 *
            <Input
              className="mt-2 font-mono"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="security-reviewer"
              autoFocus
            />
          </Label>
          <Label>
            角色名称 *
            <Input
              className="mt-2"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="安全审查员"
            />
          </Label>
        </div>

        <Label>
          描述
          <Input
            className="mt-2"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="该角色的职责范围"
          />
        </Label>

        <div>
          <div className="flex items-baseline justify-between">
            <p className="text-sm font-medium text-[#d4d4d4]">权限绑定</p>
            <span className="font-mono text-[11px] text-[#666666]">
              已选 {permissions.length} / {previewPermissions.length}
            </span>
          </div>

          <div className="mt-2.5 max-h-64 space-y-3 overflow-y-auto rounded-lg border border-[#242424] bg-[#0a0a0a] p-3.5">
            {resources.map((resource) => {
              const items = previewPermissions.filter(
                (p) => p.resource === resource,
              );
              return (
                <div key={resource}>
                  <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#525252]">
                    {resource}
                  </p>
                  <div className="mt-1.5 flex flex-wrap gap-1.5">
                    {items.map((p) => {
                      const active = permissions.includes(p.code);
                      return (
                        <button
                          key={p.code}
                          type="button"
                          onClick={() => togglePermission(p.code)}
                          title={p.description}
                          className={cn(
                            "rounded-md border px-2 py-1 font-mono text-[11px] transition-all duration-150 active:scale-95",
                            active
                              ? "border-[var(--accent-ui)] bg-[var(--accent-ui-dim)] text-white"
                              : "border-[#2a2a2a] bg-[#111111] text-[#8a8a8a] hover:border-[#4a4a4a] hover:text-white",
                          )}
                        >
                          {p.action}
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
          <FieldHint>权限采用 resource:action 编码，保存后立即生效。</FieldHint>
        </div>
      </div>
    </Dialog>
  );
}
