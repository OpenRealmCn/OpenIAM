import { previewOAuthClients } from "@/lib/preview-data";
import { CopyField } from "@/components/console/copy-field";
import { PageHeader } from "@/components/console/page-header";
import { StatusPill } from "@/components/console/status-pill";

export default function OAuthClientsPage() {
  return (
    <div>
      <PageHeader
        eyebrow="Federation"
        title="OAuth 客户端"
        description="已注册的 OpenRealm 应用与机器人。全部授权码流程强制 PKCE S256。"
      />

      <div className="space-y-4">
        {previewOAuthClients.map((client, i) => (
          <article
            key={client.clientId}
            className="animate-rise rounded-xl border border-[#222222] bg-[#0d0d0d] p-6 transition-colors duration-200 hover:border-[#3d3d3d]"
            style={{ animationDelay: `${i * 60}ms` }}
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="font-medium tracking-tight text-[#ededed]">
                    {client.name}
                  </h2>
                  <span
                    className={
                      client.type === "confidential"
                        ? "rounded-full border border-[#2e2e2e] bg-[#161616] px-2.5 py-0.5 text-[11px] text-[#a1a1a1]"
                        : "rounded-full border border-[#1b3a26] bg-[#0d1f14] px-2.5 py-0.5 text-[11px] text-[#7ee2a8]"
                    }
                  >
                    {client.type}
                  </span>
                  {client.pkce && (
                    <span className="rounded-full border border-[#2e2e2e] bg-[#111111] px-2.5 py-0.5 font-mono text-[11px] text-[#a1a1a1]">
                      PKCE S256
                    </span>
                  )}
                </div>
                <div className="mt-2.5">
                  <CopyField value={client.clientId} />
                </div>
              </div>
              <StatusPill
                tone={client.status === "active" ? "green" : "gray"}
                label={client.status === "active" ? "启用" : "停用"}
                pulse={client.status === "active"}
              />
            </div>

            <div className="mt-5 grid gap-x-10 gap-y-4 border-t border-[#1c1c1c] pt-5 sm:grid-cols-3">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#525252]">
                  授权类型
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {client.grants.map((g) => (
                    <span
                      key={g}
                      className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-[11px] text-[#a1a1a1]"
                    >
                      {g}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#525252]">
                  Scopes
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {client.scopes.map((s) => (
                    <span
                      key={s}
                      className="rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-0.5 font-mono text-[11px] text-[#7ee2a8]"
                    >
                      {s}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-[#525252]">
                  回调地址
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {client.redirectUris.length > 0 ? (
                    client.redirectUris.map((uri) => (
                      <CopyField key={uri} value={uri} />
                    ))
                  ) : (
                    <span className="text-xs text-[#525252]">
                      不适用（client_credentials）
                    </span>
                  )}
                </div>
              </div>
            </div>

            <p className="mt-4 font-mono text-[11px] text-[#525252]">
              注册于 {client.createdAt}
            </p>
          </article>
        ))}
      </div>
    </div>
  );
}
