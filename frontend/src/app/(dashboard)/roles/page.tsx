"use client";

import { useState } from "react";
import { Plus } from "lucide-react";

import { CreateRoleDialog } from "@/components/console/create-role-dialog";
import { PageHeader } from "@/components/console/page-header";
import { Reveal } from "@/components/console/reveal";
import { Button } from "@/components/ui/button";
import { useConsole } from "@/lib/store";
import { cn } from "@/lib/utils";

export default function RolesPage() {
  const { state } = useConsole();
  const [createOpen, setCreateOpen] = useState(false);
  const [flashCode, setFlashCode] = useState<string | null>(null);

  function handleCreated(code: string) {
    setFlashCode(code);
    window.setTimeout(() => setFlashCode(null), 1700);
  }

  return (
    <div>
      <PageHeader
        eyebrow="Authorization"
        title="角色"
        description="RBAC 角色目录。角色绑定权限集合，再通过用户-角色关系完成授权。"
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
                "group h-full rounded-xl border border-[#222222] bg-[#0d0d0d] p-6 transition-all duration-200 hover:-translate-y-0.5 hover:border-[#3d3d3d]",
                flashCode === role.code && "row-flash",
              )}
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="font-medium tracking-tight text-[#ededed] transition-colors group-hover:text-white">
                    {role.name}
                  </h2>
                  <p className="mt-1 font-mono text-xs text-[#666666]">
                    {role.code}
                  </p>
                </div>
                {role.isSystem && (
                  <span className="rounded-full border border-[#2e2e2e] bg-[#161616] px-2.5 py-0.5 text-[11px] text-[#a1a1a1]">
                    系统内置
                  </span>
                )}
              </div>

              <p className="mt-4 text-sm leading-6 text-[#8a8a8a]">
                {role.description}
              </p>

              <div className="mt-5 flex flex-wrap gap-1.5">
                {role.permissions.slice(0, 3).map((p) => (
                  <span
                    key={p}
                    className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-[11px] text-[#a1a1a1]"
                  >
                    {p}
                  </span>
                ))}
                {role.permissions.length > 3 && (
                  <span className="rounded-md border border-[#2a2a2a] px-2 py-0.5 font-mono text-[11px] text-[#666666]">
                    +{role.permissions.length - 3}
                  </span>
                )}
                {role.permissions.length === 0 && (
                  <span className="text-xs text-[#525252]">暂无权限</span>
                )}
              </div>

              <div className="mt-5 flex items-center justify-between border-t border-[#1c1c1c] pt-4">
                <span className="text-xs text-[#666666]">成员</span>
                <span className="font-mono text-sm text-[#ededed]">
                  {role.members}
                </span>
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
    </div>
  );
}
