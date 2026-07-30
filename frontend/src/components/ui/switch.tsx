"use client";

import { cn } from "@/lib/utils";

export function Switch({
  checked,
  onChange,
  disabled = false,
  label,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        "relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus-visible:ring-offset-2 focus-visible:ring-offset-[var(--bg)] disabled:cursor-not-allowed disabled:opacity-50",
        checked
          ? "border-transparent bg-[var(--accent)]"
          : "border-[var(--border-strong)] bg-[var(--surface-3)]",
      )}
    >
      <span
        className={cn(
          "inline-block size-4.5 transform rounded-full shadow transition-transform duration-200",
          checked
            ? "translate-x-[22px] bg-[var(--accent-fg)]"
            : "translate-x-[3px] bg-[var(--muted)]",
        )}
      />
    </button>
  );
}
