import Link from "next/link";

// Replaces Next's built-in 404 page, whose inline style attributes the CSP blocks.
export default function NotFound() {
  return (
    <div className="shell">
      <main className="card">
        <h1>404: Page not found</h1>
        <p className="lede">This page doesn&apos;t exist. Check the link you were given.</p>
        <p><Link href="/">Go to the start page</Link></p>
      </main>
    </div>
  );
}
