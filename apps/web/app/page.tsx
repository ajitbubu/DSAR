import Link from "next/link";

export default function Home() {
  return (
    <div className="shell">
      <main className="card">
        <h1>ID-PRIVACY DPAR/DSAR Automation</h1>
        <p className="lede">Data Principal request intake (M1). The operations console arrives in M2+.</p>
        <p>Development tenants: <Link href="/r/acme">Acme Retail</Link> · <Link href="/r/globex">Globex Finance</Link></p>
      </main>
    </div>
  );
}
