import { previewPermissions } from "@/lib/preview-data";
import { PageHeader } from "@/components/console/page-header";

export default function PermissionsPage() {
  const resources = [...new Set(previewPermissions.map((p) => p.resource))];

  return (
    <div>
      <PageHeader
        eyebrow="Authorization"
        title="权限"
        description="权限目录按资源分组，采用 resource:action 编码，是角色授权的最小单元。"
      />

      <div className="space-y-4">
        {resources.map((resource, i) => {
          const items = previewPermissions.filter(
            (p) => p.resource === resource,
          );
          return (
            <section
              key={resource}
              className="animate-rise rounded-xl border border-[#222222] bg-[#0d0d0d] p-6"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="flex items-baseline justify-between">
                <h2 className="font-mono text-sm text-[#ededed]">
                  {resource}
                </h2>
                <span className="font-mono text-[11px] text-[#666666]">
                  {items.length} 项
                </span>
              </div>
              <ul className="mt-4 grid gap-2 sm:grid-cols-2">
                {items.map((p) => (
                  <li
                    key={p.code}
                    className="flex items-center gap-3 rounded-lg border border-[#1f1f1f] bg-[#0a0a0a] px-3.5 py-2.5 transition-colors duration-150 hover:border-[#3d3d3d]"
                  >
                    <span className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-[11px] text-[#7ee2a8]">
                      {p.action}
                    </span>
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs text-[#d4d4d4]">
                        {p.code}
                      </p>
                      <p className="truncate text-xs text-[#666666]">
                        {p.description}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>
    </div>
  );
}
