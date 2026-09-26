import type { ReactNode } from "react";

export const metadata = {
  title: "ID-PRIVACY",
  description: "DPAR/DSAR automation",
  referrer: "no-referrer",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
