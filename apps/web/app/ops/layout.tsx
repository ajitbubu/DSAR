import Link from "next/link";
import type { ReactNode } from "react";
import { SignOut } from "./_components/SignOut";

export const metadata = { title: "Privacy operations · ID-PRIVACY" };

export default function OpsLayout({ children }: { children: ReactNode }) {
  return (
    <div className="ops-shell">
      <header className="ops-top">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span>Privacy operations</span>
        </div>
        <nav aria-label="Main">
          <Link href="/ops">Cases</Link>
          <SignOut />
        </nav>
      </header>
      <main>{children}</main>
    </div>
  );
}
