export function BrandMark() {
  return (
    <div className="flex items-center gap-2.5" aria-label="OpenIAM">
      <span
        className="block size-0 border-x-[7px] border-b-[12px] border-x-transparent border-b-[var(--fg-strong)]"
        aria-hidden="true"
      />
      <span className="text-[15px] font-semibold tracking-tight text-[var(--fg-strong)]">
        Open<span className="text-[var(--muted)]">IAM</span>
      </span>
    </div>
  );
}
