"use client";

import { useRouter } from "next/navigation";
import { type FormEvent, useRef, useState } from "react";
import { postJson, useCsrfToken } from "@/lib/client";
import {
  type ErasureFormValues,
  type FieldErrors,
  LIMITS,
  toRequestPayload,
  validateErasureForm,
} from "@/lib/validation";

const INITIAL: ErasureFormValues = {
  fullName: "",
  channel: "EMAIL",
  contact: "",
  customerId: "",
  details: "",
  residencyClaim: "IN",
  consent: false,
};

const API_FIELD: Record<string, [keyof ErasureFormValues, string]> = {
  fullName: ["fullName", "Check your name."],
  contact: ["contact", "We couldn't accept this. Use an address or number that can receive messages."],
  additionalIdentifiers: ["customerId", "Use letters, numbers and hyphens only."],
  details: ["details", "Check this field."],
  consentToProcess: ["consent", "Confirm you agree so we can process your request."],
};

function messageFor(status: number, retryAfter: string | null): string {
  if (status === 404) return "This request form isn't available. Check the link you were given.";
  if (status === 429) {
    const mins = Math.max(1, Math.ceil(Number(retryAfter ?? 60) / 60));
    return `Too many attempts. Try again in about ${mins} minute${mins === 1 ? "" : "s"}.`;
  }
  if (status === 403) return "Your session expired. Refresh the page and try again.";
  if (status === 422) return "Some details couldn't be accepted. Check the highlighted fields.";
  return "Something went wrong on our side. Please try again.";
}

export function ErasureForm({ slug }: { slug: string }) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [values, setValues] = useState(INITIAL);
  const [errors, setErrors] = useState<FieldErrors>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const summaryRef = useRef<HTMLDivElement>(null);

  const set = <K extends keyof ErasureFormValues>(key: K, value: ErasureFormValues[K]) =>
    setValues((v) => ({ ...v, [key]: value }));

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const found = validateErasureForm(values);
    setErrors(found);
    setFormError(null);
    if (Object.keys(found).length > 0 || !csrf) {
      if (!csrf) setFormError("The page isn't ready yet. Wait a moment and try again.");
      summaryRef.current?.focus();
      return;
    }
    setSubmitting(true);
    try {
      const res = await postJson("/api/public/requests", csrf, toRequestPayload(slug, values));
      if (res.status === 202) {
        router.push(`/r/${slug}/verify`);
        return;
      }
      if (res.status === 422) {
        const body = (await res.json().catch(() => ({}))) as {
          errors?: { loc?: (string | number)[] }[];
        };
        const mapped: FieldErrors = {};
        for (const e of body.errors ?? []) {
          const entry = API_FIELD[String(e.loc?.[1] ?? "")];
          if (entry) mapped[entry[0]] = entry[1];
        }
        setErrors(mapped);
      }
      setFormError(messageFor(res.status, res.headers.get("retry-after")));
      summaryRef.current?.focus();
    } catch {
      setFormError("We couldn't reach the server. Check your connection and try again.");
    } finally {
      setSubmitting(false);
    }
  }

  const invalid = (k: keyof ErasureFormValues) => (errors[k] ? true : undefined);
  const describedBy = (k: keyof ErasureFormValues, hint?: string) =>
    [hint, errors[k] ? `${k}-error` : undefined].filter(Boolean).join(" ") || undefined;

  return (
    <form onSubmit={onSubmit} noValidate>
      <div ref={summaryRef} tabIndex={-1}>
        {formError && <div className="alert error-box" role="alert">{formError}</div>}
      </div>

      <div className="field">
        <label htmlFor="fullName">Full name</label>
        <input id="fullName" type="text" autoComplete="name" maxLength={LIMITS.fullName}
               value={values.fullName} onChange={(e) => set("fullName", e.target.value)}
               aria-invalid={invalid("fullName")} aria-describedby={describedBy("fullName")} />
        {errors.fullName && <p id="fullName-error" className="error">{errors.fullName}</p>}
      </div>

      <fieldset className="field plain">
        <legend className="legend">How should we contact you?</legend>
        <p className="hint" id="channel-hint">We&apos;ll send a one-time code to confirm it&apos;s you.</p>
        <div className="segmented">
          {(["EMAIL", "SMS"] as const).map((ch) => (
            <label key={ch}>
              <input type="radio" name="channel" value={ch} checked={values.channel === ch}
                     onChange={() => set("channel", ch)} />
              <span>{ch === "EMAIL" ? "Email" : "Mobile (SMS)"}</span>
            </label>
          ))}
        </div>
        <label htmlFor="contact" className="legend">
          {values.channel === "EMAIL" ? "Email address" : "Mobile number"}
        </label>
        {values.channel === "SMS" && (
          <p className="hint" id="contact-hint">Include the country code, e.g. +919876543210</p>
        )}
        <input id="contact" type={values.channel === "EMAIL" ? "email" : "tel"}
               autoComplete={values.channel === "EMAIL" ? "email" : "tel"}
               inputMode={values.channel === "EMAIL" ? "email" : "tel"}
               maxLength={LIMITS.contact} value={values.contact}
               onChange={(e) => set("contact", e.target.value)} aria-invalid={invalid("contact")}
               aria-describedby={describedBy("contact",
                 values.channel === "SMS" ? "contact-hint" : "channel-hint")} />
        {errors.contact && <p id="contact-error" className="error">{errors.contact}</p>}
      </fieldset>

      <div className="field">
        <label htmlFor="customerId">Customer or account ID <span className="hint">(optional)</span></label>
        <p className="hint" id="customerId-hint">Helps us find records linked to you.</p>
        <input id="customerId" type="text" maxLength={LIMITS.customerId} value={values.customerId}
               onChange={(e) => set("customerId", e.target.value)} aria-invalid={invalid("customerId")}
               aria-describedby={describedBy("customerId", "customerId-hint")} />
        {errors.customerId && <p id="customerId-error" className="error">{errors.customerId}</p>}
      </div>

      <div className="field">
        <label htmlFor="details">Anything else we should know? <span className="hint">(optional)</span></label>
        <textarea id="details" maxLength={LIMITS.details} value={values.details}
                  onChange={(e) => set("details", e.target.value)} aria-invalid={invalid("details")}
                  aria-describedby={describedBy("details")} />
        {errors.details && <p id="details-error" className="error">{errors.details}</p>}
      </div>

      <div className="field">
        <label htmlFor="residency">Where do you live?</label>
        <select id="residency" value={values.residencyClaim}
                onChange={(e) => set("residencyClaim", e.target.value as ErasureFormValues["residencyClaim"])}>
          <option value="IN">India</option>
          <option value="OTHER">Another country</option>
          <option value="UNKNOWN">Prefer not to say</option>
        </select>
      </div>

      <div className="field">
        <div className="check">
          <input id="consent" type="checkbox" checked={values.consent}
                 onChange={(e) => set("consent", e.target.checked)} aria-invalid={invalid("consent")}
                 aria-describedby={describedBy("consent")} />
          <label htmlFor="consent">
            I agree that the details above can be used to verify my identity and handle this
            erasure request.
          </label>
        </div>
        {errors.consent && <p id="consent-error" className="error">{errors.consent}</p>}
      </div>

      <div className="actions">
        <button type="submit" disabled={submitting}>
          {submitting ? "Sending…" : "Continue"}
        </button>
      </div>
    </form>
  );
}
