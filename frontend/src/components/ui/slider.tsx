"use client";

export function Slider({
  value,
  min,
  max,
  step = 1,
  onChange,
  label,
}: {
  value: number;
  min: number;
  max: number;
  step?: number;
  onChange: (value: number) => void;
  label?: string;
}) {
  const percent = ((value - min) / (max - min)) * 100;

  return (
    <input
      type="range"
      aria-label={label}
      className="slider w-full"
      value={value}
      min={min}
      max={max}
      step={step}
      onChange={(e) => onChange(Number(e.target.value))}
      style={{
        background: `linear-gradient(to right, var(--accent-ui) ${percent}%, #2a2a2a ${percent}%)`,
      }}
    />
  );
}
