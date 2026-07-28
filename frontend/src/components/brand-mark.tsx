export function BrandMark() {
  return (
    <div className="flex items-center gap-2.5" aria-label="OpenIAM">
      <span
        className="block size-0 border-x-[7px] border-b-[12px] border-x-transparent border-b-white"
        aria-hidden="true"
      />
      <span className="text-[15px] font-semibold tracking-tight text-white">
        Open<span className="text-[#a1a1a1]">IAM</span>
      </span>
    </div>
  );
}
