import { ButtonHTMLAttributes, forwardRef } from "react";
import { Glyph } from "./Glyph";

export type ButtonVariant = "secondary" | "l402";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
}

const BASE =
  "font-mono inline-flex items-center gap-[6px] cursor-pointer disabled:cursor-not-allowed disabled:text-dim";

const SECONDARY =
  "bg-surface-2 text-text-dim hover:text-text border border-border px-[10px] py-[4px] text-meta";

// The single allowed loud CTA: bg-l402-bg, text-primary, border-primary.
// We avoid `cn`/twMerge here because tailwind-merge groups `text-meta` (size)
// and `text-primary` (color) as the same utility — preserving both requires
// raw string concatenation.
const L402 =
  "bg-l402-bg text-primary border border-primary px-[11px] py-[5px] text-meta";

function joinClasses(...parts: Array<string | undefined>) {
  return parts.filter(Boolean).join(" ");
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", className, children, type = "button", ...rest },
  ref,
) {
  const isL402 = variant === "l402";
  return (
    <button
      ref={ref}
      type={type}
      data-variant={variant}
      className={joinClasses(BASE, isL402 ? L402 : SECONDARY, className)}
      {...rest}
    >
      {isL402 ? <Glyph name="bolt" className="text-primary" /> : null}
      <span>{children}</span>
    </button>
  );
});
