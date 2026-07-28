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
      className="group inline-flex max-w-full items-center gap-1.5 rounded-md border border-[#2a2a2a] bg-[#111111] px-2 py-1 font-mono text-xs text-[#a1a1a1] transition-colors duration-150 hover:border-[#4a4a4a] hover:text-white"
    >
      <span className="truncate">{value}</span>
      {copied ? (
        <Check className="size-3 shrink-0 text-[#3fb950]" />
      ) : (
        <Copy className="size-3 shrink-0 opacity-0 transition-opacity duration-150 group-hover:opacity-100" />
      )}
    </button>
  );
}
