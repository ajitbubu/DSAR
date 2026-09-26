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
        <Link className="button" href={`/r/${slug}`}>Make another request</Link>
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
      <p className="hint">Keep your reference number. You&apos;ll need it if you contact us.</p>
      {c.canCancel && <CancelButton />}
    </Chrome>
  );
}
