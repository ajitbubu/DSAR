import Link from "next/link";
import { staffApi } from "@/lib/server/staff-api";
import { when } from "../_components/labels";

export const dynamic = "force-dynamic";

type QueueItem = {
  id: string;
  display_id: string;
  submitted_at: string;
  you_submitted: boolean;
};

export default async function ApprovalQueue() {
  const res = await staffApi<QueueItem[]>("/v1/approvals/queue", "/ops/approvals");
  if (!res.ok) {
    return <div className="alert error-box" role="alert">
      {res.status === 403 ? "Only approvers can see the approval queue." : "The queue couldn't be loaded."}
    </div>;
  }
  return (
    <>
      <h1>Approval queue</h1>
      <p className="lede">Cases waiting for a second person to authorise the retention decisions.</p>
      <div className="table-wrap">
        <table className="data">
          <thead><tr><th>Reference</th><th>Submitted</th><th></th></tr></thead>
          <tbody>
            {res.data.length === 0 && <tr><td colSpan={3} className="empty">Nothing waiting for approval.</td></tr>}
            {res.data.map((c) => (
              <tr key={c.id}>
                <td><Link className="mono" href={`/ops/cases/${c.id}/approval`}>{c.display_id}</Link></td>
                <td>{when(c.submitted_at)}</td>
                <td>{c.you_submitted ? <span className="hint">You submitted this, so someone else must approve</span> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
