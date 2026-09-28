import { notFound } from "next/navigation";
import { staffApi } from "@/lib/server/staff-api";
import { RegisterForm } from "./RegisterForm";

export const dynamic = "force-dynamic";

type Entry = {
  connector_id: string;
  display_name: string;
  entry_id: string | null;
  purposes: string[];
  recipients: { name: string; kind: string }[];
};

export default async function RegisterPage() {
  const res = await staffApi<Entry[]>("/v1/processing-register", "/ops/register");
  if (!res.ok) notFound();
  return (
    <>
      <h1>Processing register</h1>
      <p className="lede">
        Why each source system holds personal data, and who else receives it. Access requests
        include this, and a case can&apos;t be submitted until every system it found data in has an
        entry. Tenant admins maintain it, and every change is kept as a new version.
      </p>
      {res.data.map((e) => (
        <section key={e.connector_id} className="panel disclosure-record" aria-label={e.display_name}>
          <h2>{e.display_name} <span className="hint mono">{e.connector_id}</span></h2>
          {e.entry_id ? (
            <ul>
              {e.purposes.map((p) => <li key={p}>{p}</li>)}
              {e.recipients.map((r) => <li key={r.name}>Shared with {r.name} ({r.kind.toLowerCase()})</li>)}
            </ul>
          ) : (
            <p className="status bad">No entry yet.</p>
          )}
          <RegisterForm connectorId={e.connector_id} purposes={e.purposes} recipients={e.recipients} />
        </section>
      ))}
    </>
  );
}
