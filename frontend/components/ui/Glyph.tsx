import { cn } from "@/lib/utils";

export const GLYPHS = {
  chevron: "›",
  caret: "⌄",
  dot: "●",
  bolt: "⚡",
  search: "⌕",
  cross: "✗",
  warn: "⚠",
  sep: "·",
  cmd: "⌘",
} as const;

export type GlyphName = keyof typeof GLYPHS;

export function Glyph({
  name,
  className,
  "aria-label": ariaLabel,
}: {
  name: GlyphName;
  className?: string;
  "aria-label"?: string;
}) {
  return (
    <span
      aria-hidden={ariaLabel ? undefined : "true"}
      aria-label={ariaLabel}
      className={cn("inline-block leading-none", className)}
    >
      {GLYPHS[name]}
    </span>
  );
}
