import type { Config } from "tailwindcss";
import {
  colors,
  fontFamily,
  fontSize,
  spacing,
  borderRadius,
} from "./lib/design-tokens";

// Map each colour token to its CSS custom property so utilities react to the
// active `<html data-theme>` at runtime instead of being baked to dark hex at
// build time. The `colors` constant still drives the token *names*; the values
// it carries (dark hex) are unused here.
const colorVars = Object.fromEntries(
  Object.keys(colors).map((token) => [token, `var(--color-${token})`]),
) as Record<string, string>;

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    // Replace defaults entirely so utilities outside our token set do not compile.
    colors: colorVars,
    fontFamily: { mono: [...fontFamily.mono] } as Record<string, string[]>,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    fontSize: JSON.parse(JSON.stringify(fontSize)) as any,
    spacing: { ...spacing } as Record<string, string>,
    borderRadius: { ...borderRadius } as Record<string, string>,
    extend: {},
  },
  plugins: [],
};

export default config;
