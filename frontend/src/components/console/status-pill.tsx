import type { StatusTone } from "@/lib/preview-data";
import { cn } from "@/lib/utils";

const toneClasses: Record<StatusTone, string> = {
  green: "border-[#1b3a26] bg-[#0d1f14] text-[#7ee2a8]",
  amber: "border-[#3a2f1b] bg-[#1f1a0d] text-[#e3b341]",
  red: "border-[#3a1b1b] bg-[#1f0d0d] text-[#ffa198]",
  gray: "border-[#2a2a2a] bg-[#161616] text-[#8b949e]",
};

const dotClasses: Record<StatusTone, string> = {
  green: "bg-[#3fb950]",
  amber: "bg-[#d29922]",
  red: "bg-[#f85149]",
  gray: "bg-[#6e7681]",
};

export function StatusPill({
  tone,
  label,
  pulse = false,
}: {
  tone: StatusTone;
  label: string;
  pulse?: boolean;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        toneClasses[tone],
      )}
    >
      <span
        className={cn("size-1.5 rounded-full", dotClasses[tone], pulse && "pulse-dot")}
      />
      {label}
    </span>
  );
}
