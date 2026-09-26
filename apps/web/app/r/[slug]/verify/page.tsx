import { cookies } from "next/headers";
import Link from "next/link";
import { notFound } from "next/navigation";
import { callApi } from "@/lib/server/api";
import { serverConfig } from "@/lib/server/config";
import { COOKIE, decodeChallenge } from "@/lib/server/cookies";
import { Chrome } from "../_components/Chrome";
import { OtpForm } from "../_components/OtpForm";

export const dynamic = "force-dynamic";
const SLUG = /^[a-z0-9-]{3,40}$/;

async function devOtp(challengeId: string): Promise<string | null> {
  if (!serverConfig.devShowMockOtp) return null;
  const res = await callApi(`/v1/test-support/otp/${challengeId}`).catch(() => null);
  return res?.ok ? ((await res.json()) as { code: string }).code : null;
}

export default async function VerifyPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!SLUG.test(slug)) notFound();
  const pending = decodeChallenge((await cookies()).get(COOKIE.challenge)?.value);

  if (!pending || pending.slug !== slug) {
    return (
      <Chrome step={1}>
        <h1>Your verification session has ended</h1>
        <p className="lede">For your security, verification links expire after 30 minutes.</p>
        <Link className="button" href={`/r/${slug}`}>Start a new request</Link>
      </Chrome>
    );
  }
  const code = await devOtp(pending.challengeId);
  return (
    <Chrome step={1}>
      <h1>Confirm it&apos;s you</h1>
      <p>Request reference <span className="case-id">{pending.displayId}</span></p>
      <OtpForm slug={slug} destinationHint={pending.destinationHint} />
      {code && (
        <p className="dev-note">
          Development only: the mock OTP provider sent <strong>{code}</strong>.
        </p>
      )}
    </Chrome>
  );
}
