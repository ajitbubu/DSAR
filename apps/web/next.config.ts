import type { NextConfig } from "next";
import { securityHeaders } from "./lib/security-headers";

const config: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: [...securityHeaders] }];
  },
};

export default config;
