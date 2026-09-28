import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { STATUS_LABEL, UUID_RE, statusTone, when } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";

export const dynamic = "force-dynamic";

type MatchView = {
  id: string;
  source_record_ref: string;
  record_type: string;
  data_categories: string[];
  matched_on: string[];
  attributes: Record<string, boolean | number | string | null>;
};
type SourceView = {
  connector_id: string;
  display_name: string;
  job_status: string;
  attempts: number;
  error_code: string | null;
  finished_at: string | null;
  matches: MatchView[];
};
type DiscoveryView = { case_status: string; total_matches: number; sources: SourceView[] };

function attr(value: boolean | number | string | null): string {
  if (value === true) return "yes";
  if (value === false) return "no";
  return value === null ? "—" : String(value);
}

export default async function DiscoveryPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/discovery`;
  const [caseRes, res] = await Promise.all([
    staffApi<{ display_id: string }>(`/v1/cases/${id}`, path),
    staffApi<DiscoveryView>(`/v1/cases/${id}/discovery`, path),
  ]);
  if (!caseRes.ok || !res.ok) notFound();
  const d = res.data;
  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {caseRes.data.display_id}</p>
      <h1 className="mono">{caseRes.data.display_id}</h1>
      <p><span className={statusTone(d.case_status)}>{STATUS_LABEL[d.case_status] ?? d.case_status}</span></p>
      <CaseNav id={id} current="discovery" />
      <p className="lede">
        {d.total_matches} record{d.total_matches === 1 ? "" : "s"} found across {d.sources.length} source
        {d.sources.length === 1 ? "" : "s"}. Only pointers are stored, never record contents.
      </p>
      {d.sources.length === 0 && <p className="empty">Discovery hasn&apos;t started for this case.</p>}
      {d.sources.map((s) => (
        <section key={s.connector_id} className="source" aria-labelledby={`src-${s.connector_id}`}>
          <div className="source-head">
            <h2 id={`src-${s.connector_id}`}>{s.display_name}</h2>
            <span>
              <span className={statusTone(s.job_status)}>{s.job_status.toLowerCase()}</span>{" "}
              <span className="hint">{s.matches.length} match{s.matches.length === 1 ? "" : "es"} · {when(s.finished_at)}
                {s.error_code ? ` · error ${s.error_code}` : ""}</span>
            </span>
          </div>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr><th>Record</th><th>Type</th><th>Categories</th><th>Matched on</th><th>Attributes</th></tr>
              </thead>
              <tbody>
                {s.matches.length === 0 && (
                  <tr><td colSpan={5} className="empty">No matching records.</td></tr>
                )}
                {s.matches.map((m) => (
                  <tr key={m.id}>
                    <td className="mono">{m.source_record_ref}</td>
                    <td className="mono">{m.record_type}</td>
                    <td><div className="chips">{m.data_categories.map((c) => <span key={c} className="chip">{c}</span>)}</div></td>
                    <td>{m.matched_on.join(", ")}</td>
                    <td className="hint">
                      {Object.entries(m.attributes).map(([k, v]) => `${k.replaceAll("_", " ")}: ${attr(v)}`).join(" · ")}
                    </td>
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
