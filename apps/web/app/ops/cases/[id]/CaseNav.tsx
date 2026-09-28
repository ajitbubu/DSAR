import Link from "next/link";

type Tab = "overview" | "discovery" | "retention" | "approval" | "fulfilment" | "verification"
  | "evidence";

export function CaseNav({ id, current }: { id: string; current: Tab }) {
  const tabs = [
    { key: "overview", label: "Overview", href: `/ops/cases/${id}` },
    { key: "discovery", label: "Discovery", href: `/ops/cases/${id}/discovery` },
    { key: "retention", label: "Retention", href: `/ops/cases/${id}/retention` },
    { key: "approval", label: "Approval", href: `/ops/cases/${id}/approval` },
    { key: "fulfilment", label: "Fulfilment", href: `/ops/cases/${id}/fulfilment` },
    { key: "verification", label: "Verification", href: `/ops/cases/${id}/verification` },
    { key: "evidence", label: "Evidence", href: `/ops/cases/${id}/evidence` },
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
