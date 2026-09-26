/**
 * Client-side checks that mirror the API's allowlist schema, for fast feedback.
 * The API remains the authority; every rule here is enforced again server-side.
 */
export type ContactChannel = "EMAIL" | "SMS";
export type Residency = "IN" | "OTHER" | "UNKNOWN";

export type ErasureFormValues = {
  fullName: string;
  channel: ContactChannel;
  contact: string;
  customerId: string;
  details: string;
  residencyClaim: Residency;
  consent: boolean;
};

export type FieldErrors = Partial<Record<keyof ErasureFormValues, string>>;

export const LIMITS = { fullName: 200, contact: 254, customerId: 64, details: 2000 } as const;

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const E164 = /^\+[1-9]\d{7,14}$/;
const CUSTOMER_ID = /^[A-Za-z0-9-]+$/;
// Control and format characters, except tab and newline.
const CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u200B-\u200F\u2028-\u202E\u2060-\u206F\uFEFF]/;

export function validateErasureForm(v: ErasureFormValues): FieldErrors {
  const e: FieldErrors = {};
  const name = v.fullName.trim();
  if (!name) e.fullName = "Enter your full name.";
  else if (name.length > LIMITS.fullName) e.fullName = `Use ${LIMITS.fullName} characters or fewer.`;
  else if (CONTROL.test(name)) e.fullName = "Remove unsupported characters.";

  const contact = v.contact.trim();
  if (!contact) {
    e.contact = v.channel === "EMAIL" ? "Enter your email address." : "Enter your mobile number.";
  } else if (contact.length > LIMITS.contact) {
    e.contact = "This is too long.";
  } else if (v.channel === "EMAIL" && !EMAIL.test(contact)) {
    e.contact = "Enter an email address like name@example.com.";
  } else if (v.channel === "SMS" && !E164.test(contact)) {
    e.contact = "Enter the number with country code, like +919876543210.";
  }

  const cid = v.customerId.trim();
  if (cid && (cid.length > LIMITS.customerId || !CUSTOMER_ID.test(cid))) {
    e.customerId = "Use letters, numbers and hyphens only.";
  }
  if (v.details.length > LIMITS.details) e.details = `Use ${LIMITS.details} characters or fewer.`;
  else if (CONTROL.test(v.details.replace(/[\n\t]/g, ""))) e.details = "Remove unsupported characters.";

  if (!v.consent) e.consent = "Confirm you agree so we can process your request.";
  return e;
}

/** Builds the API payload. Blank optional fields are omitted. */
export function toRequestPayload(slug: string, v: ErasureFormValues) {
  const cid = v.customerId.trim();
  const details = v.details.trim();
  return {
    intakeSlug: slug,
    rights: ["ERASURE"],
    fullName: v.fullName.trim(),
    contact: { channel: v.channel, value: v.contact.trim() },
    additionalIdentifiers: cid ? [{ type: "CUSTOMER_ID", value: cid }] : [],
    ...(details ? { details } : {}),
    residencyClaim: v.residencyClaim,
    consentToProcess: true,
  };
}

export const OTP_PATTERN = /^\d{6}$/;
