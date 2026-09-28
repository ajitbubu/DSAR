import { notFound } from "next/navigation";
import { Chrome } from "../_components/Chrome";
import { SignInForm } from "../_components/SignInForm";

export const dynamic = "force-dynamic";
const SLUG = /^[a-z0-9-]{3,40}$/;

export default async function SignInPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  if (!SLUG.test(slug)) notFound();
  return (
    <Chrome step={1}>
      <h1>Return to your request</h1>
      <p className="lede">
        Enter the reference we gave you and the email or mobile number you used. If they match
        a request, we&apos;ll send a one-time code to confirm it&apos;s you.
      </p>
      <SignInForm slug={slug} />
    </Chrome>
  );
}
