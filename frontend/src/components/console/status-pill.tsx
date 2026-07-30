import type { StatusTone } from "@/lib/preview-data";
import { cn } from "@/lib/utils";

const toneClasses: Record<StatusTone, string> = {
  green: "border-emerald-500/30 bg-emerald-500/10 text-emerald-500",
  amber: "border-amber-500/30 bg-amber-500/10 text-amber-500",
  red: "border-red-500/30 bg-red-500/10 text-red-500",
  gray: "border-[var(--border-strong)] bg-[var(--surface-3)] text-[var(--muted)]",
};

const dotClasses: Record<StatusTone, string> = {
  green: "bg-emerald-500",
  amber: "bg-amber-500",
  red: "bg-red-500",
  gray: "bg-[var(--faint)]",
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
        className={cn(
          "size-1.5 rounded-full",
          dotClasses[tone],
          pulse && "pulse-dot",
        )}
      />
      {label}
    </span>
  );
}
