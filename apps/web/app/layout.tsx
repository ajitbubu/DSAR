import type { ReactNode } from "react";
import "./globals.css";

// Render every page per request: the CSP nonce (proxy.ts) is only applied to dynamic
// pages, so a statically prerendered page would have all its scripts blocked.
export const dynamic = "force-dynamic";

export const metadata = {
  title: "ID-PRIVACY",
  description: "Exercise your data protection rights",
  referrer: "no-referrer" as const,
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
