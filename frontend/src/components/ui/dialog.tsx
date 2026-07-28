"use client";

import { useEffect, type ReactNode } from "react";
import { X } from "lucide-react";

export function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="dialog-overlay absolute inset-0 bg-black/70"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="dialog-panel relative flex max-h-[88vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-[#2a2a2a] bg-[#0d0d0d] shadow-[0_24px_80px_rgba(0,0,0,0.7)]"
      >
        <div className="flex items-start justify-between gap-4 border-b border-[#1f1f1f] px-6 py-5">
          <div>
            <h2 className="text-lg font-semibold tracking-[-0.01em] text-white">
              {title}
            </h2>
            {description && (
              <p className="mt-1 text-sm text-[#8a8a8a]">{description}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="关闭"
            className="rounded-md p-1 text-[#666666] transition-colors hover:bg-white/5 hover:text-white"
          >
            <X className="size-4" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-5">{children}</div>

        {footer && (
          <div className="flex items-center justify-end gap-3 border-t border-[#1f1f1f] bg-[#0a0a0a] px-6 py-4">
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
