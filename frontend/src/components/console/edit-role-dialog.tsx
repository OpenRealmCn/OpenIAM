"use client";

import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { FieldHint, Input, Label } from "@/components/ui/input";
import { useConsole } from "@/lib/store";
import { useToast } from "@/components/ui/toast";
import { previewPermissions, type PreviewRole } from "@/lib/preview-data";
import { cn } from "@/lib/utils";

export function EditRoleDialog({
  role,
  onClose,
}: {
  role: PreviewRole;
  onClose: () => void;
}) {
  const { updateRole } = useConsole();
  const { toast } = useToast();

  const [name, setName] = useState(role.name);
  const [description, setDescription] = useState(role.description);
  const [permissions, setPermissions] = useState<string[]>(role.permissions);

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

  function handleSubmit() {
    if (name.trim() === "") return;
    updateRole(role.code, {
      name: name.trim(),
      description: description.trim(),
      permissions,
    });
    toast(`已更新角色 ${name}`);
    onClose();
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title="编辑角色"
      description={`调整 ${role.code} 的名称、描述与权限绑定。`}
      footer={
        <>
          <Button variant="outline" onClick={onClose}>
            取消
          </Button>
          <Button onClick={handleSubmit} disabled={name.trim() === ""}>
            保存更改
          </Button>
        </>
      }
    >
      <div className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Label>
            角色代码
            <Input className="mt-2 font-mono" value={role.code} disabled />
          </Label>
          <Label>
            角色名称 *
            <Input
              className="mt-2"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </Label>
        </div>

        <Label>
          描述
          <Input
            className="mt-2"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </Label>

        <div>
          <div className="flex items-baseline justify-between">
            <p className="text-sm font-medium text-[var(--fg)]">权限绑定</p>
            <span className="font-mono text-[11px] text-[var(--faint)]">
              已选 {permissions.length} / {previewPermissions.length}
            </span>
          </div>

          <div className="mt-2.5 max-h-64 space-y-3 overflow-y-auto rounded-lg border border-[var(--border)] bg-[var(--surface-2)] p-3.5">
            {resources.map((resource) => {
              const items = previewPermissions.filter(
                (p) => p.resource === resource,
              );
              return (
                <div key={resource}>
                  <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--faint)]">
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
                              ? "border-[var(--accent)] bg-[var(--accent-dim)] text-[var(--fg-strong)]"
                              : "border-[var(--border-strong)] bg-[var(--surface)] text-[var(--muted)] hover:border-[var(--faint)] hover:text-[var(--fg)]",
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
