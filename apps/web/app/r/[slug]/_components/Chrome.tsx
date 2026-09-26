import type { ReactNode } from "react";

const STEPS = ["Your request", "Verify", "Track"] as const;

export function Chrome({ step, children }: { step: 0 | 1 | 2; children: ReactNode }) {
  return (
    <div className="shell">
      <div className="brand">
        <span className="brand-mark" aria-hidden="true" />
        <span>Privacy rights request</span>
      </div>
      <main className="card">
        <ol className="steps" aria-label="Progress">
          {STEPS.map((label, i) => (
            <li key={label} className={i < step ? "done" : undefined}
                aria-current={i === step ? "step" : undefined}>
              {i + 1}. {label}
            </li>
          ))}
        </ol>
        {children}
      </main>
      <p className="footer">
        Your details are used only to verify your identity and handle this request.
      </p>
    </div>
  );
}
