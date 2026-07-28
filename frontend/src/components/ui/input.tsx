import type { InputHTMLAttributes, LabelHTMLAttributes } from "react";

import { cn } from "@/lib/utils";

export function Input({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-10 w-full rounded-lg border border-[#2e2e2e] bg-[#111111] px-3.5 text-sm text-white outline-none transition-colors duration-150 placeholder:text-[#525252] focus:border-[var(--accent-ui)] disabled:cursor-not-allowed disabled:opacity-60",
        className,
      )}
      {...props}
    />
  );
}

export function Label({
  className,
  ...props
}: LabelHTMLAttributes<HTMLLabelElement>) {
  return (
    <label
      className={cn(
        "block text-sm font-medium text-[#d4d4d4]",
        className,
      )}
      {...props}
    />
  );
}

export function FieldHint({ children }: { children: React.ReactNode }) {
  return <p className="mt-1.5 text-xs text-[#666666]">{children}</p>;
}
