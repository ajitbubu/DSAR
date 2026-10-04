// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

const refresh = vi.fn();
const postJson = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh }) }));
vi.mock("@/lib/client", () => ({
  useCsrfToken: () => "csrf-token",
  postJson: (...args: unknown[]) => postJson(...args),
}));

const CASE = "5b0c6a0e-6f6a-4a8e-9c1e-2d7b5d1f4a11";
const reply = (status: number, body: unknown = {}) => async () => Response.json(body, { status });
const sent = (i = 0) => {
  const [url, csrf, body, headers] = postJson.mock.calls[i] ?? [];
  return { url, csrf, body, headers };
};
const text = async (role: "alert" | "status") => (await screen.findByRole(role)).textContent;

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

import { DecisionForm } from "./DecisionForm";

const MATCH = "0f9e7d1c-2b3a-4c5d-8e6f-7a8b9c0d1e2f";
function open(currentDecision = "DELETE") {
  render(<DecisionForm caseId={CASE} matchId={MATCH} currentId="dec-1" currentDecision={currentDecision}
    decisions={["DELETE", "RETAIN", "ANONYMIZE", "MANUAL_REVIEW"]}
    codes={[{ code: "LEGAL_OBLIGATION", label: "Retention is required by law" }]} />);
  const user = userEvent.setup();
  return user.click(screen.getByRole("button", { name: "Change decision" })).then(() => user);
}

describe("DecisionForm (retention override)", () => {
  it("never offers MANUAL_REVIEW, and starts a manual-review record at Retain", async () => {
    await open("MANUAL_REVIEW");
    const decision = screen.getAllByRole("combobox")[0] as HTMLSelectElement;
    expect([...decision.options].map((o) => o.value)).toEqual(["DELETE", "RETAIN", "ANONYMIZE"]);
    expect(decision.value).toBe("RETAIN");
  });

  it("requires a reason of at least 10 characters before sending anything", async () => {
    const user = await open();
    await user.type(screen.getByLabelText(/Reason/), "too short");
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    expect(await text("alert")).toContain("at least 10 characters");
    expect(postJson).not.toHaveBeenCalled();
  });

  it("sends the override with the version it was based on, then refreshes", async () => {
    postJson.mockImplementation(reply(201));
    const user = await open();
    await user.selectOptions(screen.getAllByRole("combobox")[0]!, "ANONYMIZE");
    await user.type(screen.getByLabelText(/Reason/), "  Keep service history without identity.  ");
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(sent().url).toBe(`/api/staff/v1/cases/${CASE}/matches/${MATCH}/retention-decisions`);
    expect(sent().body).toEqual({ decision: "ANONYMIZE", exception_code: "LEGAL_OBLIGATION",
      exception_reason: "Keep service history without identity.", expected_current_id: "dec-1" });
    expect(screen.getByRole("button", { name: "Change decision" })).toBeTruthy();  // closed again
  });

  it("shows the API's explanation when someone else changed the decision first", async () => {
    postJson.mockImplementation(reply(409, { title: "Decision changed by another reviewer" }));
    const user = await open();
    await user.type(screen.getByLabelText(/Reason/), "Unpaid invoice must be kept.");
    await user.click(screen.getByRole("button", { name: "Save decision" }));
    expect(await text("alert")).toBe("Decision changed by another reviewer");
    expect(refresh).not.toHaveBeenCalled();
  });
});
