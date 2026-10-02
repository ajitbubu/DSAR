import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { STATUS_LABEL, UUID_RE, statusTone, when } from "../../_components/labels";
import { CaseNav } from "./CaseNav";

export const dynamic = "force-dynamic";

type CaseDetail = {
  id: string;
  display_id: string;
  status: string;
  rights: string[];
  submitted_at: string;
  due_at: string | null;
  policy_pack: string | null;
  workflow: string | null;
  identifiers: { type: string; masked: string; assurance: string }[];
  jurisdiction: { outcome: string; policy_pack: string | null; rationale: string } | null;
  minimised_at: string | null;
};

export default async function CasePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const res = await staffApi<CaseDetail>(`/v1/cases/${id}`, `/ops/cases/${id}`);
  if (!res.ok) notFound();
  const c = res.data;
  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {c.display_id}</p>
      <h1 className="mono">{c.display_id}</h1>
      <p><span className={statusTone(c.status)}>{STATUS_LABEL[c.status] ?? c.status}</span></p>
      <CaseNav id={c.id} current="overview" />
      <div className="grid-2">
        <section className="panel">
          <h2>Request</h2>
          <dl className="meta">
            <dt>Right</dt><dd>{c.rights.join(", ")}</dd>
            <dt>Submitted</dt><dd>{when(c.submitted_at)}</dd>
            <dt>Respond by</dt><dd>{c.due_at ? when(c.due_at) : "Not set (SLA not yet validated)"}</dd>
            <dt>Workflow</dt><dd className="mono">{c.workflow ?? "—"}</dd>
          </dl>
        </section>
        <section className="panel">
          <h2>Jurisdiction</h2>
          {c.jurisdiction ? (
            <dl className="meta">
              <dt>Policy</dt><dd className="mono">{c.jurisdiction.policy_pack ?? "None applies"}</dd>
              <dt>Basis</dt><dd>{c.jurisdiction.rationale}</dd>
            </dl>
          ) : <p className="hint">Not decided yet.</p>}
        </section>
      </div>
      <section className="panel">
        <h2>Identifiers</h2>
        <p className="hint">Only verified identifiers are used to search connected systems.</p>
        {c.minimised_at ? (
          <p className="empty">
            The requester&apos;s identifiers were deleted on {when(c.minimised_at)}, after the
            post-closure retention period.
          </p>
        ) : c.identifiers.length === 0 ? (
          <p className="empty">Identity resolution hasn&apos;t run yet for this case.</p>
        ) : (
        <div className="table-wrap">
          <table className="data">
            <thead><tr><th>Type</th><th>Value</th><th>Assurance</th></tr></thead>
            <tbody>
              {c.identifiers.map((i) => (
                <tr key={`${i.type}-${i.masked}`}>
                  <td>{i.type}</td>
                  <td className="mono">{i.masked}</td>
                  <td><span className={i.assurance === "VERIFIED" ? "status ok" : "status"}>
                    {i.assurance === "VERIFIED" ? "Verified" : "Claimed, not used"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </section>
    </>
  );
}
