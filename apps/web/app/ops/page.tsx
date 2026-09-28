import Link from "next/link";
import { staffApi } from "@/lib/server/staff-api";
import { STATUS_LABEL, statusTone, when } from "./_components/labels";

export const dynamic = "force-dynamic";

type CaseSummary = {
  id: string;
  display_id: string;
  status: string;
  rights: string[];
  submitted_at: string;
  due_at: string | null;
  policy_pack: string | null;
};

export default async function CasesPage() {
  const res = await staffApi<{ items: CaseSummary[] }>("/v1/cases?limit=50", "/ops");
  if (!res.ok) {
    return <div className="alert error-box" role="alert">
      {res.status === 403 ? "Your role can't view cases." : "Cases couldn't be loaded."}
    </div>;
  }
  const cases = res.data.items;
  return (
    <>
      <h1>Cases</h1>
      <p className="lede">Most recent 50 requests for your organisation.</p>
      <div className="table-wrap">
        <table className="data">
          <thead>
            <tr><th>Reference</th><th>Right</th><th>Status</th><th>Policy</th><th>Submitted</th></tr>
          </thead>
          <tbody>
            {cases.length === 0 && (
              <tr><td colSpan={5} className="empty">No requests yet.</td></tr>
            )}
            {cases.map((c) => (
              <tr key={c.id}>
                <td><Link className="mono" href={`/ops/cases/${c.id}`}>{c.display_id}</Link></td>
                <td>{c.rights.join(", ")}</td>
                <td><span className={statusTone(c.status)}>{STATUS_LABEL[c.status] ?? c.status}</span></td>
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
