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
              className="animate-rise rounded-xl border border-[var(--border)] bg-[var(--surface)] p-6"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="flex items-baseline justify-between">
                <h2 className="font-mono text-sm text-[var(--fg-strong)]">
                  {resource}
                </h2>
                <span className="font-mono text-[11px] text-[var(--faint)]">
                  {items.length} 项
                </span>
              </div>
              <ul className="mt-4 grid gap-2 sm:grid-cols-2">
                {items.map((p) => (
                  <li
                    key={p.code}
                    className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface-2)] px-3.5 py-2.5 transition-colors duration-150 hover:border-[var(--border-strong)]"
                  >
                    <span className="rounded-md border border-[var(--border-strong)] bg-[var(--surface)] px-2 py-0.5 font-mono text-[11px] text-emerald-500">
                      {p.action}
                    </span>
                    <div className="min-w-0">
                      <p className="truncate font-mono text-xs text-[var(--fg)]">
                        {p.code}
                      </p>
                      <p className="truncate text-xs text-[var(--faint)]">
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
