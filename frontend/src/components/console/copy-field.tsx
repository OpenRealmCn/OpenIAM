"use client";

import { useState } from "react";
import { Check, Copy } from "lucide-react";

export function CopyField({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={copied ? "已复制" : "点击复制"}
      className="group inline-flex max-w-full items-center gap-1.5 rounded-md border border-[var(--border-strong)] bg-[var(--surface-2)] px-2 py-1 font-mono text-xs text-[var(--muted)] transition-colors duration-150 hover:border-[var(--faint)] hover:text-[var(--fg)]"
    >
      <span className="truncate">{value}</span>
      {copied ? (
        <Check className="size-3 shrink-0 text-emerald-500" />
      ) : (
        <Copy className="size-3 shrink-0 opacity-0 transition-opacity duration-150 group-hover:opacity-100" />
      )}
    </button>
  );
}
