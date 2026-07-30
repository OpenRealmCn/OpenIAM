export type ThemeMode = "light" | "dark" | "auto";

export interface ThemeTokens {
  bg: string;
  surface: string;
  surface2: string;
  surface3: string;
  fg: string;
  fgStrong: string;
  muted: string;
  faint: string;
  border: string;
  borderStrong: string;
  accent: string;
  accentFg: string;
}

export interface Theme {
  id: string;
  name: string;
  dark: ThemeTokens;
  light: ThemeTokens;
}

export const CUSTOM_THEME_ID = "custom";

const DARK_BASE: ThemeTokens = {
  bg: "#0a0a0a",
  surface: "#111111",
  surface2: "#161616",
  surface3: "#1d1d1d",
  fg: "#ededed",
  fgStrong: "#ffffff",
  muted: "#a1a1a1",
  faint: "#6b6b6b",
  border: "#262626",
  borderStrong: "#3d3d3d",
  accent: "#ffffff",
  accentFg: "#0a0a0a",
};

const LIGHT_BASE: ThemeTokens = {
  bg: "#fafafa",
  surface: "#ffffff",
  surface2: "#f4f4f5",
  surface3: "#ebebed",
  fg: "#26262a",
  fgStrong: "#09090b",
  muted: "#5b5b63",
  faint: "#9d9da6",
  border: "#e6e6e9",
  borderStrong: "#cfcfd4",
  accent: "#0a0a0a",
  accentFg: "#ffffff",
};

const dark = (o: Partial<ThemeTokens>): ThemeTokens => ({ ...DARK_BASE, ...o });
const light = (o: Partial<ThemeTokens>): ThemeTokens => ({
  ...LIGHT_BASE,
  ...o,
});

const theme = (
  id: string,
  name: string,
  d: Partial<ThemeTokens>,
  l: Partial<ThemeTokens>,
): Theme => ({ id, name, dark: dark(d), light: light(l) });

export const themes: Theme[] = [
  theme("default", "Default", { accent: "#ffffff", bg: "#000000" }, { accent: "#0a0a0a" }),
  theme("amethyst-haze", "Amethyst Haze", { accent: "#b794f6", bg: "#13101c", surface: "#1a1626" }, { accent: "#805ad5", bg: "#faf8fc" }),
  theme("bold-tech", "Bold Tech", { accent: "#00e5ff", bg: "#050a0e", surface: "#0a141b" }, { accent: "#0077b6", bg: "#f5f9fc" }),
  theme("bubblegum", "Bubblegum", { accent: "#ff7ac6", bg: "#170d13", surface: "#20121b" }, { accent: "#ec4899", bg: "#fdf5f9" }),
  theme("caffeine", "Caffeine", { accent: "#c8a27a", bg: "#120e0a", surface: "#1a140e" }, { accent: "#8b5e34", bg: "#faf6f0" }),
  theme("candyland", "Candyland", { accent: "#ff6b9d", bg: "#150f14", surface: "#1e141c" }, { accent: "#f472b6", bg: "#fff5f8" }),
  theme("catppuccin", "Catppuccin", { accent: "#cba6f7", bg: "#1e1e2e", surface: "#181825", surface2: "#1f1f30", border: "#313244", borderStrong: "#45475a", muted: "#a6adc8", faint: "#7f849c", fg: "#cdd6f4", fgStrong: "#f5f5f7" }, { accent: "#8839ef", bg: "#eff1f5", surface: "#e6e9ef", surface2: "#dce0e8", border: "#ccd0da", borderStrong: "#bcc0cc", muted: "#5c5f77", faint: "#8c8fa1", fg: "#4c4f69", fgStrong: "#383a42" }),
  theme("claude", "Claude", { accent: "#e0885f", bg: "#1a1612", surface: "#211c16", surface2: "#282119", border: "#3a3128", borderStrong: "#4d4136", fg: "#ece5d8", fgStrong: "#f7f1e6", muted: "#b3a894", faint: "#7d7362" }, { accent: "#d97757", accentFg: "#ffffff", bg: "#f5f0e6", surface: "#faf6ec", surface2: "#efe8d8", border: "#e3dac6", borderStrong: "#d3c7ad", fg: "#3d3929", fgStrong: "#2a2618", muted: "#6f6753", faint: "#a2987f" }),
  theme("claymorphism", "Claymorphism", { accent: "#e07a5f", bg: "#141210", surface: "#1c1917", surface2: "#23201d" }, { accent: "#c96f4a", bg: "#f7f3ee", surface: "#efe9e1", surface2: "#e7dfd4" }),
  theme("clean-slate", "Clean Slate", { accent: "#94a3b8", bg: "#0b0f14", surface: "#111820" }, { accent: "#475569", bg: "#f8fafc" }),
  theme("cosmic-night", "Cosmic Night", { accent: "#818cf8", bg: "#0a0c1a", surface: "#11142a" }, { accent: "#6366f1", bg: "#f6f7fd" }),
  theme("cyberpunk", "Cyberpunk", { accent: "#fcee0a", accentFg: "#0d0221", bg: "#0d0221", surface: "#16082e", surface2: "#1e0d3a", border: "#3a1d5e", borderStrong: "#5a2d8e", fg: "#f5e9ff", fgStrong: "#ffffff", muted: "#b794d6", faint: "#7d5a9e" }, { accent: "#c7b900", accentFg: "#1a1600", bg: "#f7f5e8", surface: "#fffef5", border: "#e0dcbf", borderStrong: "#c9c49a", fg: "#2a2600", fgStrong: "#1a1600", muted: "#6f6a3d", faint: "#a39d6b" }),
  theme("darkmatter", "Darkmatter", { accent: "#a78bfa", bg: "#050505", surface: "#0d0d0f" }, { accent: "#7c3aed", bg: "#fafafa" }),
  theme("doom-64", "Doom 64", { accent: "#ff4655", bg: "#0c0a09", surface: "#171310", surface2: "#1f1a16", border: "#332a22", borderStrong: "#4d3d30", fg: "#d6cfc4", fgStrong: "#f2ede4", muted: "#9c9184", faint: "#6b6156" }, { accent: "#c22f3d", bg: "#f7f2ee", surface: "#efe7df", surface2: "#e6dcd1", border: "#d8cbbb", borderStrong: "#c4b39e", fg: "#3a2f26", fgStrong: "#241c15", muted: "#6f6153", faint: "#a2927f" }),
  theme("elegant-luxury", "Elegant Luxury", { accent: "#d4af37", bg: "#0d0b07", surface: "#16130c" }, { accent: "#b08d2f", bg: "#faf7f0" }),
  theme("graphite", "Graphite", { accent: "#d4d4d8", accentFg: "#18181b", bg: "#0a0a0a", surface: "#141414" }, { accent: "#3f3f46", bg: "#fafafa" }),
  theme("kodama-grove", "Kodama Grove", { accent: "#86efac", bg: "#0a120d", surface: "#101c14" }, { accent: "#3f9159", bg: "#f5faf6" }),
  theme("midnight-bloom", "Midnight Bloom", { accent: "#c084fc", bg: "#0a0e1a", surface: "#111726" }, { accent: "#9333ea", bg: "#f7f5fd" }),
  theme("mocha-mousse", "Mocha Mousse", { accent: "#a47864", bg: "#120e0c", surface: "#1a1512" }, { accent: "#8a6248", bg: "#faf5f0" }),
  theme("nature", "Nature", { accent: "#4ade80", bg: "#0a100b", surface: "#101a12" }, { accent: "#2f9e44", bg: "#f5faf5" }),
  theme("neo-brutalism", "Neo Brutalism", { accent: "#fbbf24", accentFg: "#1a1600", bg: "#0c0a09", surface: "#171412", border: "#3d3d3d", borderStrong: "#666666" }, { accent: "#f59e0b", accentFg: "#1a1600", bg: "#fffdf5", surface: "#ffffff", border: "#1a1a1a", borderStrong: "#000000", fg: "#1a1a1a", fgStrong: "#000000", muted: "#4d4d4d", faint: "#8a8a8a" }),
  theme("northern-lights", "Northern Lights", { accent: "#5eead4", bg: "#071013", surface: "#0d1a1e" }, { accent: "#0d9488", bg: "#f2fbf9" }),
  theme("notebook", "Notebook", { accent: "#60a5fa", bg: "#111318", surface: "#181b21" }, { accent: "#2563eb", bg: "#fdfcf7", surface: "#ffffff", surface2: "#f6f3e9", border: "#e6e0cf", borderStrong: "#d3cbb4", fg: "#2f2c22", fgStrong: "#1c1a12", muted: "#6b6656", faint: "#a39d8a" }),
  theme("ocean-breeze", "Ocean Breeze", { accent: "#22d3ee", bg: "#071015", surface: "#0d1a21" }, { accent: "#0891b2", bg: "#f3fafc" }),
  theme("pastel-dreams", "Pastel Dreams", { accent: "#f9a8d4", bg: "#12101a", surface: "#1a1724" }, { accent: "#f472b6", bg: "#fdf7fb" }),
  theme("perpetuity", "Perpetuity", { accent: "#2dd4bf", bg: "#0a1012", surface: "#101a1c" }, { accent: "#0f766e", bg: "#f5fbfa" }),
  theme("quantum-rose", "Quantum Rose", { accent: "#fb7185", bg: "#140b0e", surface: "#1e1116" }, { accent: "#e11d48", bg: "#fdf5f7" }),
  theme("retro-arcade", "Retro Arcade", { accent: "#ff2a6d", bg: "#0d0221", surface: "#160a2e", border: "#3a1d5e", borderStrong: "#5a2d8e", fg: "#ffe9f5", fgStrong: "#ffffff", muted: "#d69ec4", faint: "#9e5f8a" }, { accent: "#d6336c", bg: "#fdf3f7", surface: "#ffffff", border: "#f0cfe0", borderStrong: "#e0a8c8", fg: "#3d1226", fgStrong: "#2a0a1a", muted: "#8a4d6b", faint: "#c08aa5" }),
  theme("sage-garden", "Sage Garden", { accent: "#a3b899", bg: "#0d120c", surface: "#141c12" }, { accent: "#7d9471", bg: "#f7faf5" }),
  theme("soft-pop", "Soft Pop", { accent: "#fb923c", bg: "#14100c", surface: "#1e1812" }, { accent: "#f97316", bg: "#fdf8f3" }),
  theme("solar-dusk", "Solar Dusk", { accent: "#fb923c", bg: "#120c14", surface: "#1c1220" }, { accent: "#ea580c", bg: "#fdf6f0" }),
  theme("starry-night", "Starry Night", { accent: "#93c5fd", bg: "#070b1a", surface: "#0e1428" }, { accent: "#3b82f6", bg: "#f5f8fd" }),
  theme("sunset-horizon", "Sunset Horizon", { accent: "#fb7185", bg: "#140d10", surface: "#1e1418" }, { accent: "#f43f5e", bg: "#fdf5f6" }),
  theme("supabase", "Supabase", { accent: "#3ecf8e", bg: "#1c1c1c", surface: "#232323", surface2: "#2a2a2a" }, { accent: "#16a34a", bg: "#fafafa" }),
  theme("t3-chat", "T3 Chat", { accent: "#f97316", bg: "#0f0f10", surface: "#17171a" }, { accent: "#ea580c", bg: "#fafafa" }),
  theme("tangerine", "Tangerine", { accent: "#fb923c", bg: "#140e08", surface: "#1e150d" }, { accent: "#ea580c", bg: "#fdf7f2" }),
  theme("twitter", "Twitter", { accent: "#1d9bf0", bg: "#15202b", surface: "#1e2c3a", surface2: "#253341", border: "#38444d", borderStrong: "#4a5a66", fg: "#e7e9ea", fgStrong: "#ffffff", muted: "#8b98a5", faint: "#66757f" }, { accent: "#1d9bf0", bg: "#ffffff", surface: "#f7f9f9", surface2: "#eff3f4", border: "#eff3f4", borderStrong: "#cfd9de", fg: "#0f1419", fgStrong: "#0f1419", muted: "#536471", faint: "#8b98a5" }),
  theme("vercel", "Vercel", { accent: "#ffffff", bg: "#000000", surface: "#0a0a0a" }, { accent: "#000000", bg: "#ffffff", surface: "#fafafa" }),
  theme("vintage-paper", "Vintage Paper", { accent: "#c8a27a", bg: "#171310", surface: "#1f1a15", border: "#332b22", borderStrong: "#4d4133", fg: "#e3d8c6", fgStrong: "#f2ead9", muted: "#a89a82", faint: "#756a56" }, { accent: "#9a6b4f", accentFg: "#ffffff", bg: "#f4ecd8", surface: "#faf4e4", surface2: "#efe6cf", border: "#e0d4b8", borderStrong: "#cdbd9c", fg: "#4a3f2e", fgStrong: "#332b1e", muted: "#7a6c52", faint: "#ab9c7f" }),
  theme("violet-bloom", "Violet Bloom", { accent: "#a78bfa", bg: "#100c1a", surface: "#181226" }, { accent: "#7c3aed", bg: "#f8f5fd" }),
];

export function getTheme(id: string): Theme {
  return themes.find((t) => t.id === id) ?? themes[0];
}

export function hexToRgba(hex: string, alpha: number): string {
  const raw = hex.replace("#", "");
  const full =
    raw.length === 3
      ? raw
          .split("")
          .map((c) => c + c)
          .join("")
      : raw;
  const value = parseInt(full, 16);
  if (Number.isNaN(value)) return `rgba(255,255,255,${alpha})`;
  const r = (value >> 16) & 255;
  const g = (value >> 8) & 255;
  const b = value & 255;
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

export function resolveTokens(
  themeId: string,
  mode: ThemeMode,
  systemDark: boolean,
  custom?: { light: Partial<ThemeTokens>; dark: Partial<ThemeTokens> },
): { tokens: ThemeTokens; effective: "light" | "dark" } {
  const effective: "light" | "dark" =
    mode === "auto" ? (systemDark ? "dark" : "light") : mode;

  if (themeId === CUSTOM_THEME_ID && custom) {
    const base = effective === "dark" ? DARK_BASE : LIGHT_BASE;
    const overrides = effective === "dark" ? custom.dark : custom.light;
    return { tokens: { ...base, ...overrides }, effective };
  }

  const t = getTheme(themeId);
  return { tokens: effective === "dark" ? t.dark : t.light, effective };
}

export function applyTokens(tokens: ThemeTokens, effective: "light" | "dark") {
  const root = document.documentElement;
  root.style.setProperty("--bg", tokens.bg);
  root.style.setProperty("--surface", tokens.surface);
  root.style.setProperty("--surface-2", tokens.surface2);
  root.style.setProperty("--surface-3", tokens.surface3);
  root.style.setProperty("--fg", tokens.fg);
  root.style.setProperty("--fg-strong", tokens.fgStrong);
  root.style.setProperty("--muted", tokens.muted);
  root.style.setProperty("--faint", tokens.faint);
  root.style.setProperty("--border", tokens.border);
  root.style.setProperty("--border-strong", tokens.borderStrong);
  root.style.setProperty("--accent", tokens.accent);
  root.style.setProperty("--accent-fg", tokens.accentFg);
  root.style.setProperty("--accent-dim", hexToRgba(tokens.accent, 0.2));
  root.style.setProperty("--ring", hexToRgba(tokens.accent, 0.5));
  root.style.colorScheme = effective;
  root.dataset.theme = effective;
}
