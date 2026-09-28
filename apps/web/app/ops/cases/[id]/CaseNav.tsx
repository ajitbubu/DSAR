import Link from "next/link";

type Tab = "overview" | "discovery" | "retention";

export function CaseNav({ id, current }: { id: string; current: Tab }) {
  const tabs = [
    { key: "overview", label: "Overview", href: `/ops/cases/${id}` },
    { key: "discovery", label: "Discovery", href: `/ops/cases/${id}/discovery` },
    { key: "retention", label: "Retention", href: `/ops/cases/${id}/retention` },
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
