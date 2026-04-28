import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Standalone output bundles only the prod node_modules needed at runtime
  // (~50MB vs ~500MB), so the EC2 host can run `node .next/standalone/server.js`
  // without `pnpm install` or `pnpm build`. See openspec change deploy-frontend-ci.
  output: "standalone",
};

export default nextConfig;
