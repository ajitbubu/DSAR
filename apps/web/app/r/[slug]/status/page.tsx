import { cookies, headers } from "next/headers";
import Link from "next/link";
import { notFound } from "next/navigation";
import { callApi } from "@/lib/server/api";
import { COOKIE } from "@/lib/server/cookies";
import { CancelButton } from "../_components/CancelButton";
import { Chrome } from "../_components/Chrome";

export const dynamic = "force-dynamic";
const SLUG = /^[a-z0-9-]{3,40}$/;

type PublicCase = {
  displayId: string;
  status: string;
  submittedAt: string;
  dueAt: string | null;
  completionResponse: string | null;
  canCancel: boolean;
  report: {
    available: boolean;
    availableUntil: string;
    downloadsLeft: number;
    records: number;
    withheld: number;
  } | null;
};

const EXPLAIN: Record<string, string> = {
  Verifying: "We're waiting for you to confirm your identity.",
  "In progress": "We've verified your identity and are working on your request.",
  Completed: "We've finished processing your request.",
  Closed: "This request is closed.",
  Cancelled: "You withdrew this request. No further action will be taken.",
  "Verification failed": "We couldn't verify your identity, so this request was not processed.",
};

const HEADING: Record<string, string> = {
  Cancelled: "Request withdrawn",
  "Verification failed": "We couldn't verify your identity",
  Completed: "Your request is complete",
  Closed: "Your request is closed",
};

function formatDate(iso: string): string {
  return new Intl.DateTimeFormat("en-IN", { dateStyle: "long", timeStyle: "short",
                                            timeZone: "Asia/Kolkata" }).format(new Date(iso));
}

export default async function StatusPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!SLUG.test(slug)) notFound();
  const token = (await cookies()).get(COOKIE.dpSession)?.value;
  const ip = ((await headers()).get("x-forwarded-for") ?? "").split(",")[0]?.trim();
  const res = token ? await callApi("/v1/public/case", { dpSession: token, clientIp: ip }) : null;

  if (!res || res.status === 401) {
    return (
      <Chrome step={2}>
        <h1>Your tracking session has ended</h1>
        <p className="lede">
          Sessions expire after 30 minutes of inactivity. We&apos;ll contact you when your
          request is complete.
        </p>
        <div className="actions">
          <Link className="button" href={`/r/${slug}/signin`}>Return to your request</Link>
          <Link className="button secondary" href={`/r/${slug}`}>Make another request</Link>
        </div>
      </Chrome>
    );
  }
  if (!res.ok) throw new Error("Could not load request status");
  const c = (await res.json()) as PublicCase;

  return (
    <Chrome step={2}>
      <h1>{HEADING[c.status] ?? "We've received your request"}</h1>
      <p className="lede">{EXPLAIN[c.status] ?? "We're working on your request."}</p>
      <dl className="meta">
        <dt>Reference</dt>
        <dd className="case-id">{c.displayId}</dd>
        <dt>Status</dt>
        <dd><span className="badge">{c.status}</span></dd>
        <dt>Submitted</dt>
        <dd>{formatDate(c.submittedAt)}</dd>
        {c.dueAt && (<><dt>Respond by</dt><dd>{formatDate(c.dueAt)}</dd></>)}
      </dl>
      {c.completionResponse && <div className="alert success">{c.completionResponse}</div>}
      {c.report && (
        <section className="report" aria-labelledby="report-heading">
          <h2 id="report-heading">Your copy of your data</h2>
          {c.report.available ? (
            <>
              <p>
                {c.report.records} record{c.report.records === 1 ? "" : "s"}
                {c.report.withheld > 0 && `, with ${c.report.withheld} item${c.report.withheld === 1 ? "" : "s"} withheld`}.
                Available until {formatDate(c.report.availableUntil)}; {c.report.downloadsLeft} download
                {c.report.downloadsLeft === 1 ? "" : "s"} left.
              </p>
              <div className="actions">
                <a className="button" href="/api/public/report/html" download>Download (readable page)</a>
                <a className="button secondary" href="/api/public/report/json" download>Download (JSON)</a>
              </div>
            </>
          ) : (
            <p className="hint">This copy is no longer available. Contact us if you need another.</p>
          )}
        </section>
      )}
      <p className="hint">Keep your reference number. You&apos;ll need it if you contact us.</p>
      {c.canCancel && <CancelButton />}
    </Chrome>
  );
}
