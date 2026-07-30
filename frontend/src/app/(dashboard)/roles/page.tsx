"use client";

import { useState } from "react";
import { Pencil, Plus, Trash2 } from "lucide-react";

import { CreateRoleDialog } from "@/components/console/create-role-dialog";
import { EditRoleDialog } from "@/components/console/edit-role-dialog";
import { PageHeader } from "@/components/console/page-header";
import { Reveal } from "@/components/console/reveal";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { useToast } from "@/components/ui/toast";
import { useConsole } from "@/lib/store";
import type { PreviewRole } from "@/lib/preview-data";
import { cn } from "@/lib/utils";

export default function RolesPage() {
  const { state, deleteRole } = useConsole();
  const { toast } = useToast();
  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<PreviewRole | null>(null);
  const [deleting, setDeleting] = useState<PreviewRole | null>(null);
  const [flashCode, setFlashCode] = useState<string | null>(null);

  function handleCreated(code: string) {
    setFlashCode(code);
    window.setTimeout(() => setFlashCode(null), 1700);
  }

  function confirmDelete() {
    if (!deleting) return;
    deleteRole(deleting.code);
    toast(`已删除角色 ${deleting.name}`, "info");
    setDeleting(null);
  }

  return (
    <div>
      <PageHeader
        eyebrow="Authorization"
        title="角色"
        description="RBAC 角色目录。角色可创建、编辑与删除，绑定权限集合后通过用户-角色关系完成授权。"
      >
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="size-4" />
          创建角色
        </Button>
      </PageHeader>

      <div className="grid gap-4 lg:grid-cols-2">
        {state.roles.map((role, i) => (
          <Reveal key={role.code} delay={(i % 4) * 60}>
            <article
              className={cn(
                "group flex h-full flex-col rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6 transition-all duration-200 hover:-translate-y-0.5 hover:border-[var(--border-strong)]",
                flashCode === role.code && "row-flash",
              )}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="font-medium tracking-tight text-[var(--fg-strong)]">
                    {role.name}
                  </h2>
                  <p className="mt-1 font-mono text-xs text-[var(--faint)]">
                    {role.code}
                  </p>
                </div>
                {role.isSystem && (
                  <span className="rounded-full border border-[var(--border-strong)] bg-[var(--surface-2)] px-2.5 py-0.5 text-[11px] text-[var(--muted)]">
                    系统内置
                  </span>
                )}
              </div>

              <p className="mt-4 text-sm leading-6 text-[var(--muted)]">
                {role.description}
              </p>

              <div className="mt-5 flex flex-wrap gap-1.5">
                {role.permissions.slice(0, 3).map((p) => (
                  <span
                    key={p}
                    className="rounded-md border border-[var(--border-strong)] bg-[var(--surface-2)] px-2 py-0.5 font-mono text-[11px] text-[var(--muted)]"
                  >
                    {p}
                  </span>
                ))}
                {role.permissions.length > 3 && (
                  <span className="rounded-md border border-[var(--border-strong)] px-2 py-0.5 font-mono text-[11px] text-[var(--faint)]">
                    +{role.permissions.length - 3}
                  </span>
                )}
                {role.permissions.length === 0 && (
                  <span className="text-xs text-[var(--faint)]">暂无权限</span>
                )}
              </div>

              <div className="mt-5 flex items-center justify-between border-t border-[var(--border)] pt-4">
                <span className="font-mono text-xs text-[var(--faint)]">
                  {role.members} 名成员
                </span>
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    onClick={() => setEditing(role)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] px-2.5 py-1.5 text-xs text-[var(--muted)] transition-colors hover:border-[var(--faint)] hover:text-[var(--fg)]"
                  >
                    <Pencil className="size-3" />
                    编辑
                  </button>
                  <button
                    type="button"
                    disabled={role.isSystem}
                    onClick={() => setDeleting(role)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-strong)] px-2.5 py-1.5 text-xs text-[var(--muted)] transition-colors hover:border-red-500/40 hover:bg-red-500/10 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-[var(--border-strong)] disabled:hover:bg-transparent disabled:hover:text-[var(--muted)]"
                  >
                    <Trash2 className="size-3" />
                    删除
                  </button>
                </div>
              </div>
            </article>
          </Reveal>
        ))}
      </div>

      {createOpen && (
        <CreateRoleDialog
          onClose={() => setCreateOpen(false)}
          onCreated={handleCreated}
        />
      )}

      {editing && (
        <EditRoleDialog role={editing} onClose={() => setEditing(null)} />
      )}

      {deleting && (
        <Dialog
          open
          onClose={() => setDeleting(null)}
          title="删除角色"
          description={`确定要删除角色「${deleting.name}」吗？已分配该角色的用户将被解除绑定。`}
          footer={
            <>
              <Button variant="outline" onClick={() => setDeleting(null)}>
                取消
              </Button>
              <Button variant="danger" onClick={confirmDelete}>
                <Trash2 className="size-4" />
                确认删除
              </Button>
            </>
          }
        >
          <p className="text-sm leading-6 text-[var(--muted)]">
            此操作会同时移除该角色与{" "}
            <span className="font-mono text-[var(--fg)]">{deleting.members}</span>{" "}
            名成员的绑定关系，且无法撤销。
          </p>
        </Dialog>
      )}
    </div>
  );
}
