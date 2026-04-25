import type { Config } from "tailwindcss";
import {
  colors,
  fontFamily,
  fontSize,
  spacing,
  borderRadius,
} from "./lib/design-tokens";

// The `as const` codegen output is readonly; Tailwind expects mutable types.
// Cast through `unknown` is the lightest way to bridge — values are identical.
const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    // Replace defaults entirely so utilities outside our token set do not compile.
    colors: { ...colors } as Record<string, string>,
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
