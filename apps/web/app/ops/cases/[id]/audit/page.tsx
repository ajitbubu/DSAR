import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { UUID_RE, when } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";
import { VerifyChain } from "./VerifyChain";

export const dynamic = "force-dynamic";

type Event = {
  seq: number;
  occurred_at: string;
  actor_type: string;
  actor_ref: string;
  action: string;
  object_type: string;
  details: Record<string, unknown>;
  hash: string;
};

export default async function AuditPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/audit`;
  const [caseRes, res] = await Promise.all([
    staffApi<{ display_id: string }>(`/v1/cases/${id}`, path),
    staffApi<Event[]>(`/v1/cases/${id}/audit-events`, path),
  ]);
  if (!caseRes.ok || !res.ok) notFound();
  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {caseRes.data.display_id}</p>
      <h1 className="mono">{caseRes.data.display_id}</h1>
      <CaseNav id={id} current="audit" />
      <div className="summary-bar">
        <span className="hint">{res.data.length} events · append-only · each linked to the previous by SHA-256</span>
        <VerifyChain />
      </div>
      <div className="table-wrap">
        <table className="data">
          <thead><tr><th>#</th><th>When</th><th>Actor</th><th>Action</th><th>Details</th></tr></thead>
          <tbody>
            {res.data.map((e) => (
              <tr key={e.seq}>
                <td className="mono">{e.seq}</td>
                <td>{when(e.occurred_at)}</td>
                <td>{e.actor_type.toLowerCase()}<div className="hint mono">{e.actor_ref.slice(0, 24)}</div></td>
                <td className="mono">{e.action}<div className="hint">{e.object_type} · {e.hash.slice(0, 10)}…</div></td>
                <td><pre className="details">{JSON.stringify(e.details)}</pre></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
