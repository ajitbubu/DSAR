import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { DECISION_LABEL, STATUS_LABEL, UUID_RE, decisionTone, statusTone, when } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";
import { DecisionForm } from "./DecisionForm";
import { LegalHoldForm } from "./LegalHoldForm";
import { ReviewActions } from "./ReviewActions";

export const dynamic = "force-dynamic";

type Decision = {
  id: string;
  decision: string;
  source: string;
  rule_id: string | null;
  exception_code: string | null;
  exception_reason: string | null;
  legal_hold_id: string | null;
  created_at: string;
};
type Item = {
  match_id: string;
  connector_id: string;
  source_record_ref: string;
  record_type: string;
  data_categories: string[];
  current: Decision | null;
  history: Decision[];
};
type RetentionView = {
  case_status: string;
  case_version: number;
  counts: Record<string, number>;
  unresolved_manual_review: number;
  items: Item[];
  exception_codes: { code: string; label: string; reference: string | null }[];
  decisions_allowed: string[];
};

function basis(d: Decision, labels: Map<string, string>): string {
  if (d.source === "ENGINE") {
    const code = d.exception_code ? ` · ${labels.get(d.exception_code) ?? d.exception_code}` : "";
    return `Rule ${d.rule_id}${code}`;
  }
  return `${labels.get(d.exception_code ?? "") ?? d.exception_code}: ${d.exception_reason}`;
}

export default async function RetentionPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/retention`;
  const [caseRes, res] = await Promise.all([
    staffApi<{ display_id: string }>(`/v1/cases/${id}`, path),
    staffApi<RetentionView>(`/v1/cases/${id}/retention`, path),
  ]);
  if (!caseRes.ok || !res.ok) notFound();
  const v = res.data;
  const labels = new Map(v.exception_codes.map((c) => [c.code, c.label]));
  const editable = v.case_status === "UNDER_REVIEW";

  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {caseRes.data.display_id}</p>
      <h1 className="mono">{caseRes.data.display_id}</h1>
      <p><span className={statusTone(v.case_status)}>{STATUS_LABEL[v.case_status] ?? v.case_status}</span></p>
      <CaseNav id={id} current="retention" />

      {v.items.length === 0 ? (
        <p className="empty">No retention decisions yet. They&apos;re made once discovery finishes.</p>
      ) : (
        <>
          <div className="summary-bar">
            {Object.entries(v.counts).map(([d, n]) => (
              <span key={d}><span className={decisionTone(d)}>{DECISION_LABEL[d] ?? d}</span> {n}</span>
            ))}
            <ReviewActions caseId={id} status={v.case_status} version={v.case_version}
                           unresolved={v.unresolved_manual_review} />
          </div>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>Record</th><th>Source</th><th>Decision</th><th>Basis</th></tr>
              </thead>
              <tbody>
                {v.items.map((item) => (
                  <tr key={item.match_id}>
                    <td className="mono">{item.source_record_ref}<div className="hint">{item.record_type}</div></td>
                    <td>{item.connector_id}<div className="chips">{item.data_categories.map((c) => <span key={c} className="chip">{c}</span>)}</div></td>
                    <td>
                      {item.current && (
                        <span className={decisionTone(item.current.decision)}>
                          {DECISION_LABEL[item.current.decision] ?? item.current.decision}
                        </span>
                      )}
                      {item.current?.legal_hold_id && <div className="hint">Legal hold</div>}
                    </td>
                    <td>
                      {item.current && basis(item.current, labels)}
                      {item.history.length > 1 && (
                        <details className="history">
                          <summary>History ({item.history.length})</summary>
                          <ol>
                            {item.history.map((h) => (
                              <li key={h.id}>
                                {DECISION_LABEL[h.decision] ?? h.decision} · {h.source === "ENGINE" ? "engine" : "analyst"} · {when(h.created_at)}
                              </li>
                            ))}
                          </ol>
                        </details>
                      )}
                      {editable && item.current && (
                        <DecisionForm caseId={id} matchId={item.match_id} currentId={item.current.id}
                                      currentDecision={item.current.decision}
                                      decisions={v.decisions_allowed} codes={v.exception_codes} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <section className="panel legal-hold">
        <h2>Legal hold</h2>
        <p className="hint">A hold makes every record in scope “Retain”, including cases already under review.</p>
        <LegalHoldForm caseId={id} />
      </section>
    </>
  );
}
