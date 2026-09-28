import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { STATUS_LABEL, UUID_RE, statusTone, when } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";
import { RetryButton } from "./RetryButton";

export const dynamic = "force-dynamic";

type Execution = {
  operation: string;
  attempt_no: number;
  outcome: string;
  error_code: string | null;
  receipt_id: string | null;
  replayed: boolean | null;
  evidence_sha256: string | null;
  finished_at: string;
};
type Task = {
  id: string;
  source_record_ref: string;
  connector_id: string;
  action: string;
  status: string;
  attempt_count: number;
  skip_reason: string | null;
  receipt_id: string | null;
  outcome: string | null;
  last_error_code: string | null;
  executions: Execution[];
};
type View = { case_status: string; counts: Record<string, number>; tasks: Task[] };

const ACTION: Record<string, string> = {
  DELETE: "Delete", ANONYMIZE: "Anonymise", RESTRICT: "Restrict", NOOP_RETAIN: "Retain (no action)",
};

export default async function FulfilmentPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/fulfilment`;
  const [caseRes, res] = await Promise.all([
    staffApi<{ display_id: string }>(`/v1/cases/${id}`, path),
    staffApi<View>(`/v1/cases/${id}/fulfilment-tasks`, path),
  ]);
  if (!caseRes.ok || !res.ok) notFound();
  const v = res.data;
  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {caseRes.data.display_id}</p>
      <h1 className="mono">{caseRes.data.display_id}</h1>
      <p><span className={statusTone(v.case_status)}>{STATUS_LABEL[v.case_status] ?? v.case_status}</span></p>
      <CaseNav id={id} current="fulfilment" />
      {v.tasks.length === 0 ? (
        <p className="empty">Nothing to execute yet. Tasks are created when a case is approved.</p>
      ) : (
        <>
          <div className="summary-bar">
            {Object.entries(v.counts).map(([s, n]) => (
              <span key={s}><span className={statusTone(s)}>{s.toLowerCase().replaceAll("_", " ")}</span> {n}</span>
            ))}
          </div>
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Record</th><th>Action</th><th>Status</th><th>Attempts &amp; evidence</th></tr></thead>
              <tbody>
                {v.tasks.map((t) => (
                  <tr key={t.id}>
                    <td className="mono">{t.source_record_ref}<div className="hint">{t.connector_id}</div></td>
                    <td>{ACTION[t.action] ?? t.action}</td>
                    <td>
                      <span className={statusTone(t.status)}>{t.status.toLowerCase().replaceAll("_", " ")}</span>
                      {t.skip_reason && <div className="hint">{t.skip_reason}</div>}
                      {t.outcome && <div className="hint">{t.outcome.toLowerCase().replaceAll("_", " ")}</div>}
                    </td>
                    <td className="hint">
                      {t.executions.length === 0 && (t.action === "NOOP_RETAIN" ? "No connector call" : "Not dispatched yet")}
                      {t.executions.map((e) => (
                        <div key={`${e.operation}-${e.attempt_no}`}>
                          {e.operation === "execute_action" ? `Attempt ${e.attempt_no}` : "Evidence"}: {e.outcome.toLowerCase().replaceAll("_", " ")}
                          {e.error_code ? ` (${e.error_code})` : ""}{e.replayed ? " · replayed" : ""}
                          {e.evidence_sha256 ? <span className="mono"> · {e.evidence_sha256.slice(0, 12)}…</span> : null}
                          {" · "}{when(e.finished_at)}
                        </div>
                      ))}
                      {t.status === "FAILED_FINAL" && <RetryButton caseId={id} taskId={t.id} />}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}
