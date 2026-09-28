import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { STATUS_LABEL, UUID_RE, statusTone, when } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";
import { ReviewActions } from "../retention/ReviewActions";
import { ExclusionToggle } from "./ExclusionToggle";
import { ExportButton, RefreshWhilePending } from "./ExportButton";

export const dynamic = "force-dynamic";

type Field = {
  name: string;
  label: string;
  category: string;
  value: string | number | boolean | null;
  excluded: boolean;
  reason_code: string | null;
};
type DisclosureRecord = {
  match_id: string;
  connector_id: string;
  record_type: string;
  excluded: boolean;
  reason_code: string | null;
  fields: Field[];
};
export type DisclosureView = {
  export: {
    id: string;
    round: number;
    status: string;
    error_code: string | null;
    record_count: number;
    field_count: number;
    missing_count: number;
    finished_at: string | null;
  } | null;
  records: DisclosureRecord[];
  missing: string[];
  processing: {
    connector_id: string;
    display_name: string;
    entry_id: string | null;
    purposes: string[];
    recipients: { name: string; kind: string }[];
  }[];
  reason_codes: { code: string; label: string }[];
  disclosure_set_sha256: string | null;
};
type CaseDetail = { display_id: string; status: string; version: number };

function show(v: Field["value"]): string {
  if (v === null) return "—";
  return String(v);
}

export default async function DisclosurePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/disclosure`;
  const [caseRes, res] = await Promise.all([
    staffApi<CaseDetail>(`/v1/cases/${id}`, path),
    staffApi<DisclosureView>(`/v1/cases/${id}/disclosure`, path),
  ]);
  if (!caseRes.ok) notFound();
  const c = caseRes.data;
  const header = (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {c.display_id}</p>
      <h1 className="mono">{c.display_id}</h1>
      <p><span className={statusTone(c.status)}>{STATUS_LABEL[c.status] ?? c.status}</span></p>
      <CaseNav id={id} current="disclosure" />
    </>
  );
  if (!res.ok) {
    return (
      <>
        {header}
        <p className="empty">
          {res.status === 403
            ? "Your role can't view exported personal data."
            : "This case has no disclosure. Only access requests do."}
        </p>
      </>
    );
  }
  const v = res.data;
  const labels = new Map(v.reason_codes.map((r) => [r.code, r.label]));
  const editable = c.status === "UNDER_REVIEW" && v.export?.status === "READY";
  const pending = v.export?.status === "PENDING" || v.export?.status === "RUNNING";

  return (
    <>
      {header}
      <div className="summary-bar">
        {v.export ? (
          <span>
            Export round {v.export.round}: <strong>{v.export.status.toLowerCase()}</strong>
            {v.export.status === "READY" && ` · ${v.export.record_count} records, ${v.export.field_count} fields`}
            {v.export.error_code && ` · ${v.export.error_code}`}
            {v.export.finished_at && <span className="hint"> · {when(v.export.finished_at)}</span>}
          </span>
        ) : (
          <span>No export yet.</span>
        )}
        {c.status === "UNDER_REVIEW" && !pending && (
          <ExportButton caseId={id} again={v.export !== null} />
        )}
        <ReviewActions caseId={id} status={c.status} version={c.version} unresolved={0} />
      </div>
      {pending && <RefreshWhilePending />}
      <p className="hint">
        Withhold anything that isn&apos;t the requester&apos;s to receive, such as another person&apos;s data.
        Every change is recorded, and a separate approver authorises the final set.
      </p>

      {v.missing.length > 0 && (
        <div className="alert" role="status">
          {v.missing.length} record{v.missing.length === 1 ? "" : "s"} found during discovery{" "}
          {v.missing.length === 1 ? "is" : "are"} no longer held by the source system.
        </div>
      )}

      {v.records.map((r) => (
        <section key={r.match_id} className={`panel disclosure-record${r.excluded ? " withheld" : ""}`}
                 aria-label={`${r.connector_id} ${r.record_type}`}>
          <h2>
            {r.record_type} <span className="hint">{r.connector_id}</span>
            {r.excluded && (
              <span className="status bad"> withheld · {labels.get(r.reason_code ?? "") ?? r.reason_code}</span>
            )}
          </h2>
          {editable && v.export && (
            <ExclusionToggle caseId={id} exportId={v.export.id} matchId={r.match_id} field={null}
                             excluded={r.excluded} codes={v.reason_codes} label="record" />
          )}
          <div className="table-wrap">
            <table className="data">
              <thead><tr><th>Field</th><th>Value</th><th>Category</th><th>Disclose</th></tr></thead>
              <tbody>
                {r.fields.map((f, i) => (
                  <tr key={`${f.name}-${i}`} className={f.excluded || r.excluded ? "withheld" : undefined}>
                    <td>{f.label}<div className="hint mono">{f.name}</div></td>
                    <td>{show(f.value)}</td>
                    <td><span className="chip">{f.category}</span></td>
                    <td>
                      {f.excluded
                        ? `Withheld · ${labels.get(f.reason_code ?? "") ?? f.reason_code}`
                        : r.excluded ? "Withheld with record" : "Yes"}
                      {editable && v.export && !r.excluded && (
                        <ExclusionToggle caseId={id} exportId={v.export.id} matchId={r.match_id}
                                         field={f.name} excluded={f.excluded} codes={v.reason_codes}
                                         label={f.label} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}

      <section className="panel legal-hold">
        <h2>How this data is processed</h2>
        <p className="hint">From the processing register. The requester receives this with their data.</p>
        <ul>
          {v.processing.map((p) => (
            <li key={p.connector_id}>
              <strong>{p.display_name}</strong>:{" "}
              {p.entry_id ? (
                <>
                  {p.purposes.join("; ")}
                  {p.recipients.length > 0 && ` · shared with ${p.recipients.map((x) => `${x.name} (${x.kind.toLowerCase()})`).join(", ")}`}
                </>
              ) : (
                <span className="status bad">no register entry, so this can&apos;t be submitted yet</span>
              )}
            </li>
          ))}
        </ul>
        <Link href="/ops/register">Edit the processing register</Link>
      </section>
    </>
  );
}
