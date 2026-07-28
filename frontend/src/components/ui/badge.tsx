import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

export function Badge({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border border-[#2a2a2a] bg-[#161616] px-2.5 py-0.5 text-[11px] font-medium text-[#a1a1a1]",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Separator({ className }: { className?: string }) {
  return <div className={cn("h-px w-full bg-[#1f1f1f]", className)} />;
}
