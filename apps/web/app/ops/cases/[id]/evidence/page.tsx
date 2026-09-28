import Link from "next/link";
import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { STATUS_LABEL, UUID_RE, statusTone, when } from "../../../_components/labels";
import { CaseNav } from "../CaseNav";
import { UploadForm } from "./UploadForm";

export const dynamic = "force-dynamic";

type Artifact = {
  id: string;
  kind: string;
  sha256: string;
  manifest_sha256: string | null;
  size_bytes: number;
  media_type: string;
  created_at: string;
};

function size(n: number): string {
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
}

export default async function EvidencePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!UUID_RE.test(id)) notFound();
  const path = `/ops/cases/${id}/evidence`;
  const [caseRes, res] = await Promise.all([
    staffApi<{ display_id: string; status: string }>(`/v1/cases/${id}`, path),
    staffApi<Artifact[]>(`/v1/cases/${id}/evidence`, path),
  ]);
  if (!caseRes.ok || !res.ok) notFound();
  const packages = res.data.filter((a) => a.kind === "PACKAGE");
  const uploads = res.data.filter((a) => a.kind === "UPLOAD");
  return (
    <>
      <p className="crumbs"><Link href="/ops">Cases</Link> / {caseRes.data.display_id}</p>
      <h1 className="mono">{caseRes.data.display_id}</h1>
      <p><span className={statusTone(caseRes.data.status)}>{STATUS_LABEL[caseRes.data.status] ?? caseRes.data.status}</span></p>
      <CaseNav id={id} current="evidence" />

      <section className="panel">
        <h2>Evidence package</h2>
        {packages.length === 0 ? (
          <p className="hint">Generated automatically once verification passes.</p>
        ) : packages.map((p) => (
          <div key={p.id}>
            <dl className="meta">
              <dt>Generated</dt><dd>{when(p.created_at)}</dd>
              <dt>Size</dt><dd>{size(p.size_bytes)}</dd>
              <dt>Manifest SHA-256</dt><dd className="mono">{p.manifest_sha256}</dd>
              <dt>Package SHA-256</dt><dd className="mono">{p.sha256}</dd>
            </dl>
            <a className="button" href={`/api/staff-download/v1/cases/${id}/evidence/${p.id}/content`}>
              Download package
            </a>
            <p className="hint">Downloads are recorded in the audit trail. The manifest hash is also anchored there.</p>
          </div>
        ))}
      </section>

      <section className="panel legal-hold">
        <h2>Supporting documents</h2>
        {uploads.length > 0 && (
          <ul>
            {uploads.map((u) => (
              <li key={u.id}>
                <a href={`/api/staff-download/v1/cases/${id}/evidence/${u.id}/content`}>
                  {u.media_type} · {size(u.size_bytes)}
                </a>{" "}<span className="hint">{when(u.created_at)} · <span className="mono">{u.sha256.slice(0, 12)}…</span></span>
              </li>
            ))}
          </ul>
        )}
        <UploadForm caseId={id} />
      </section>
    </>
  );
}
