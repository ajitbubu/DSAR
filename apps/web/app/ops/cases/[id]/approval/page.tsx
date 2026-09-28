import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { DECISION_LABEL, STATUS_LABEL, UUID_RE, decisionTone, statusTone, when } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";
import { ApprovalForm } from "./ApprovalForm";

export const dynamic = "force-dynamic";

type RetentionView = {
  case_status: string;
  case_version: number;
  decision_set_sha256: string;
  items: {
    match_id: string;
    connector_id: string;
    source_record_ref: string;
    current: { decision: string; exception_code: string | null; exception_reason: string | null;
               source: string; rule_id: string | null } | null;
  }[];
};
type ApprovalView = { id: string; outcome: string; comment: string | null; created_at: string };

export default async function ApprovalPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/approval`;
  const [caseRes, retRes, histRes] = await Promise.all([
    staffApi<{ display_id: string }>(`/v1/cases/${id}`, path),
    staffApi<RetentionView>(`/v1/cases/${id}/retention`, path),
    staffApi<ApprovalView[]>(`/v1/cases/${id}/approvals`, path),
  ]);
  if (!caseRes.ok || !retRes.ok || !histRes.ok) notFound();
  const v = retRes.data;
  const toDelete = v.items.filter((i) => i.current?.decision === "DELETE").length;

  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {caseRes.data.display_id}</p>
      <h1 className="mono">{caseRes.data.display_id}</h1>
      <p><span className={statusTone(v.case_status)}>{STATUS_LABEL[v.case_status] ?? v.case_status}</span></p>
      <CaseNav id={id} current="approval" />

      {v.case_status === "PENDING_APPROVAL" && (
        <section className="panel">
          <h2>Authorise these decisions</h2>
          <p>Approving lets the platform act on {toDelete} record{toDelete === 1 ? "" : "s"} marked Delete.
            You can&apos;t approve a case you submitted or changed.</p>
          <ApprovalForm caseId={id} version={v.case_version} digest={v.decision_set_sha256} />
        </section>
      )}

      <h2>Decisions</h2>
      <div className="table-wrap">
        <table className="data">
          <thead><tr><th>Record</th><th>Source</th><th>Decision</th><th>Basis</th></tr></thead>
          <tbody>
            {v.items.map((i) => (
              <tr key={i.match_id}>
                <td className="mono">{i.source_record_ref}</td>
                <td>{i.connector_id}</td>
                <td>{i.current && <span className={decisionTone(i.current.decision)}>{DECISION_LABEL[i.current.decision]}</span>}</td>
                <td>{i.current?.source === "ANALYST_OVERRIDE"
                  ? `${i.current.exception_code}: ${i.current.exception_reason}`
                  : `Rule ${i.current?.rule_id ?? "—"}`}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section className="panel legal-hold">
        <h2>Approval history</h2>
        {histRes.data.length === 0 ? <p className="hint">No decisions yet.</p> : (
          <ol>
            {histRes.data.map((a) => (
              <li key={a.id}>
                <span className={a.outcome === "APPROVED" ? "status ok" : "status bad"}>{a.outcome.toLowerCase()}</span>{" "}
                {when(a.created_at)}{a.comment ? ` — ${a.comment}` : ""}
              </li>
            ))}
          </ol>
        )}
      </section>
    </>
  );
}
