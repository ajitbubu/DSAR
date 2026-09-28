import Link from "next/link";
import { notFound } from "next/navigation";
import { Chrome } from "./_components/Chrome";
import { ErasureForm } from "./_components/ErasureForm";

export const dynamic = "force-dynamic";
const SLUG = /^[a-z0-9-]{3,40}$/;

export default async function RequestPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!SLUG.test(slug)) notFound();
  return (
    <Chrome step={0}>
      <h1>Make a request about your personal data</h1>
      <p className="lede">
        Ask us to delete the personal data we hold about you, or to send you a copy of it.
      </p>
      <ErasureForm slug={slug} />
      <p className="hint">
        Already made a request? <Link href={`/r/${slug}/signin`}>Return to your request</Link>.
      </p>
    </Chrome>
  );
}
