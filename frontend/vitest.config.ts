import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    // jsdom ≥29 refuses localStorage on opaque origins; give tests a real URL.
    environmentOptions: { jsdom: { url: "http://localhost:3000/" } },
    globals: true,
    setupFiles: ["./vitest.setup.ts"],
    include: ["**/__tests__/**/*.test.{ts,tsx}"],
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "."),
    },
  },
});
