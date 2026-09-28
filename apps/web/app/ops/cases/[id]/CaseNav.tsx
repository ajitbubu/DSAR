import Link from "next/link";

export function CaseNav({ id, current }: { id: string; current: "overview" | "discovery" }) {
  const tabs = [
    { key: "overview", label: "Overview", href: `/ops/cases/${id}` },
    { key: "discovery", label: "Discovery", href: `/ops/cases/${id}/discovery` },
  ] as const;
  return (
    <nav className="subnav" aria-label="Case sections">
      {tabs.map((t) => (
        <Link key={t.key} href={t.href} aria-current={t.key === current ? "page" : undefined}>
          {t.label}
        </Link>
      ))}
    </nav>
  );
}
