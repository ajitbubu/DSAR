import Link from "next/link";
import { staffApi } from "@/lib/server/staff-api";
import { SLA_LABEL, STATUS_LABEL, slaTone, statusTone, when } from "./_components/labels";

export const dynamic = "force-dynamic";

type CaseSummary = {
  id: string;
  display_id: string;
  status: string;
  rights: string[];
  submitted_at: string;
  policy_pack: string | null;
  sla_state: string;
};
type Summary = {
  by_status: Record<string, number>;
  by_sla: Record<string, number>;
  awaiting_approval: number;
  needs_attention: number;
};

const FILTERS = ["RETENTION_EVALUATED", "UNDER_REVIEW", "PENDING_APPROVAL",
                 "RECONCILIATION_REQUIRED", "PENDING_MANUAL_HANDLING", "CLOSED"];
const STATUS_RE = /^[A-Z_]{3,40}$/;

export default async function Dashboard({ searchParams }: { searchParams: Promise<{ status?: string }> }) {
  const { status } = await searchParams;
  const filter = status && STATUS_RE.test(status) ? status : undefined;
  const qs = new URLSearchParams({ limit: "50", ...(filter ? { status: filter } : {}) });
  const [casesRes, sumRes] = await Promise.all([
    staffApi<{ items: CaseSummary[] }>(`/v1/cases?${qs}`, "/ops"),
    staffApi<Summary>("/v1/dashboard/summary", "/ops"),
  ]);
  if (!casesRes.ok || !sumRes.ok) {
    const forbidden = !casesRes.ok && casesRes.status === 403;
    return <div className="alert error-box" role="alert">
      {forbidden ? "Your role can't view cases." : "Cases couldn't be loaded."}
    </div>;
  }
  const s = sumRes.data;
  const open = Object.entries(s.by_status).filter(([k]) => !["CLOSED", "CANCELLED", "VERIFICATION_FAILED"].includes(k))
    .reduce((n, [, v]) => n + v, 0);
  return (
    <>
      <h1>Privacy operations</h1>
      <div className="tiles" role="list" aria-label="Summary">
        <div className="tile" role="listitem"><div className="n">{open}</div><div className="l">Open requests</div></div>
        <div className="tile" role="listitem"><div className="n">{s.needs_attention}</div><div className="l">Need an analyst</div></div>
        <div className="tile" role="listitem"><div className="n">{s.awaiting_approval}</div><div className="l">Awaiting approval</div></div>
        <div className="tile" role="listitem"><div className="n">{s.by_sla.OVERDUE ?? 0}</div><div className="l">Overdue</div></div>
        <div className="tile" role="listitem"><div className="n">{s.by_sla.UNVALIDATED ?? 0}</div><div className="l">Deadline not validated</div></div>
      </div>
      {(s.by_sla.UNVALIDATED ?? 0) > 0 && (
        <p className="hint">Response deadlines in the current policy pack haven&apos;t been legally validated,
          so due dates aren&apos;t set (open decision D-9).</p>
      )}
      <nav className="filters" aria-label="Filter by status">
        <Link className={!filter ? "chip status" : "chip"} href="/ops">All</Link>
        {FILTERS.map((f) => (
          <Link key={f} className={filter === f ? "chip status" : "chip"} href={`/ops?status=${f}`}>
            {STATUS_LABEL[f] ?? f} {s.by_status[f] ? `(${s.by_status[f]})` : ""}
          </Link>
        ))}
      </nav>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr><th>Reference</th><th>Right</th><th>Status</th><th>Deadline</th><th>Policy</th><th>Submitted</th></tr>
          </thead>
          <tbody>
            {casesRes.data.items.length === 0 && (
              <tr><td colSpan={6} className="empty">No requests match.</td></tr>
            )}
            {casesRes.data.items.map((c) => (
              <tr key={c.id}>
                <td><Link className="mono" href={`/ops/cases/${c.id}`}>{c.display_id}</Link></td>
                <td>{c.rights.join(", ")}</td>
                <td><span className={statusTone(c.status)}>{STATUS_LABEL[c.status] ?? c.status}</span></td>
                <td><span className={slaTone(c.sla_state)}>{SLA_LABEL[c.sla_state] ?? c.sla_state}</span></td>
                <td className="mono">{c.policy_pack ?? "—"}</td>
                <td>{when(c.submitted_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
