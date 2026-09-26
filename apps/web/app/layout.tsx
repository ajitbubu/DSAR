import type { ReactNode } from "react";
import "./globals.css";

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
