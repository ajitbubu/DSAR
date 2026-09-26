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
      <h1>Request erasure of your personal data</h1>
      <p className="lede">
        Ask us to delete personal data we hold about you. Some records may have to be kept by
        law; if so, we&apos;ll tell you which and why.
      </p>
      <ErasureForm slug={slug} />
    </Chrome>
  );
}
