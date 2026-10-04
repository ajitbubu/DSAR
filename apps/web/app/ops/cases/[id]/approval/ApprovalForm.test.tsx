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

import { ApprovalForm } from "./ApprovalForm";

const DIGEST = "ab".repeat(32);
const show = () => render(<ApprovalForm caseId={CASE} version={7} digest={DIGEST} />);

describe("ApprovalForm", () => {
  it("binds the approval to the exact decision set and case version", async () => {
    postJson.mockImplementation(reply(201));
    show();
    await userEvent.setup().click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(sent().url).toBe(`/api/staff/v1/cases/${CASE}/approvals`);
    expect(sent().body).toEqual({ outcome: "APPROVED", case_version: 7, decision_set_sha256: DIGEST });
  });

  it("reuses one idempotency key per outcome, so a double click can't decide twice", async () => {
    postJson.mockImplementation(reply(500, { title: "Try again" }));
    show();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Approve" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(postJson).toHaveBeenCalledTimes(2));
    const [first, second] = [sent(0).headers["Idempotency-Key"], sent(1).headers["Idempotency-Key"]];
    expect(first).toMatch(/^[a-f0-9]{32}-approved$/);
    expect(second).toBe(first);
  });

  it("requires a comment of at least 10 characters to reject", async () => {
    show();
    await userEvent.setup().click(screen.getByRole("button", { name: "Reject" }));
    expect(await text("alert")).toContain("at least 10 characters");
    expect(postJson).not.toHaveBeenCalled();
  });

  it("sends a rejection with its comment and a different key", async () => {
    postJson.mockImplementation(reply(201));
    show();
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/Comment/), "Invoice must be retained, not deleted.");
    await user.click(screen.getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(sent().body).toMatchObject({ outcome: "REJECTED", comment: "Invoice must be retained, not deleted." });
    expect(sent().headers["Idempotency-Key"]).toMatch(/-rejected$/);
  });
});
