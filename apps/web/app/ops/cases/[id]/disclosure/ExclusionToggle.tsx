"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { useCsrfToken } from "@/lib/client";
import { staffPost } from "../../../_components/staffPost";

type Props = {
  caseId: string;
  exportId: string;
  matchId: string;
  field: string | null; // null = the whole record
  excluded: boolean;
  codes: { code: string; label: string }[];
  label: string;
};

export function ExclusionToggle({ caseId, exportId, matchId, field, excluded, codes, label }: Props) {
  const router = useRouter();
  const csrf = useCsrfToken();
  const [code, setCode] = useState(
    codes.find((c) => c.code === "THIRD_PARTY_DATA")?.code ?? codes[0]?.code ?? "",
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function send(action: "EXCLUDE" | "INCLUDE") {
    if (!csrf) return;
    setBusy(true);
    setError(null);
    const r = await staffPost(`/v1/cases/${caseId}/disclosure/exclusions`, csrf, {
      export_id: exportId, data_match_id: matchId, field_name: field, action,
      reason_code: action === "EXCLUDE" ? code : null,
    });
    setBusy(false);
    if (r.ok) router.refresh();
    else setError(r.title ?? "That didn't work.");
  }

  if (excluded) {
    return (
      <div className="exclusion">
        {error && <div className="alert error-box" role="alert">{error}</div>}
        <button type="button" className="secondary" onClick={() => send("INCLUDE")} disabled={busy || !csrf}>
          Disclose {field === null ? "record" : ""}
        </button>
      </div>
    );
  }
  return (
    <div className="exclusion">
      {error && <div className="alert error-box" role="alert">{error}</div>}
      <label>
        <span className="sr-only">Reason for withholding {label}</span>
        <select value={code} onChange={(e) => setCode(e.target.value)}>
          {codes.map((c) => <option key={c.code} value={c.code}>{c.label}</option>)}
        </select>
      </label>
      <button type="button" className="secondary" onClick={() => send("EXCLUDE")} disabled={busy || !csrf}
              aria-label={`Withhold ${label}`}>
        Withhold
      </button>
    </div>
  );
}
