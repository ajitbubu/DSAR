import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { STATUS_LABEL, UUID_RE, statusTone } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";
import { ReconcileButton } from "./ReconcileButton";

export const dynamic = "force-dynamic";

type Result = {
  source_record_ref: string;
  connector_id: string;
  round: number;
  expected: string;
  observed_verify: string | null;
  observed_rescan: string | null;
  outcome: string;
  note: string | null;
};
type View = { case_status: string; latest_round: number | null; results: Result[] };

const lower = (s: string | null) => (s ? s.toLowerCase() : "—");

export default async function VerificationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/verification`;
  const [caseRes, res] = await Promise.all([
    staffApi<{ display_id: string }>(`/v1/cases/${id}`, path),
    staffApi<View>(`/v1/cases/${id}/verification`, path),
  ]);
  if (!caseRes.ok || !res.ok) notFound();
  const v = res.data;
  const rounds = [...new Set(v.results.map((r) => r.round))];
  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {caseRes.data.display_id}</p>
      <h1 className="mono">{caseRes.data.display_id}</h1>
      <p><span className={statusTone(v.case_status)}>{STATUS_LABEL[v.case_status] ?? v.case_status}</span></p>
      <CaseNav id={id} current="verification" />
      <p className="lede">Each record is checked twice: the source system&apos;s own answer, and an
        independent rescan with the requester&apos;s verified identifiers.</p>
      {v.case_status === "RECONCILIATION_REQUIRED" && <ReconcileButton caseId={id} />}
      {rounds.length === 0 && <p className="empty">Verification hasn&apos;t run yet.</p>}
      {rounds.map((round) => (
        <section key={round} className="source" aria-labelledby={`round-${round}`}>
          <h2 id={`round-${round}`}>Round {round}</h2>
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Record</th><th>Expected</th><th>Source says</th><th>Rescan</th><th>Result</th></tr></thead>
              <tbody>
                {v.results.filter((r) => r.round === round).map((r) => (
                  <tr key={`${round}-${r.source_record_ref}`}>
                    <td className="mono">{r.source_record_ref}<div className="hint">{r.connector_id}</div></td>
                    <td>{lower(r.expected)}</td>
                    <td>{lower(r.observed_verify)}</td>
                    <td>{r.observed_rescan === "PRESENT" ? "found" : r.observed_rescan === "ABSENT" ? "not found" : "—"}</td>
                    <td><span className={r.outcome === "PASS" ? "status ok" : "status bad"}>{r.outcome.toLowerCase()}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </>
  );
}
