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

import { ReviewActions } from "./ReviewActions";

const show = (status: string, unresolved = 0) =>
  render(<ReviewActions caseId={CASE} status={status} version={4} unresolved={unresolved} />);
const button = (name: string) => screen.queryByRole("button", { name }) as HTMLButtonElement | null;

describe("ReviewActions", () => {
  it.each([
    ["RETENTION_EVALUATED", "Start review", "BEGIN_REVIEW"],
    ["DISCOVERY_COMPLETE", "Start review", "BEGIN_REVIEW"],
    ["REJECTED", "Resume review", "REWORK"],
    ["UNDER_REVIEW", "Submit for approval", "SUBMIT_FOR_APPROVAL"],
  ])("in %s offers %s and fires %s with the expected version", async (status, name, event) => {
    postJson.mockImplementation(reply(200));
    show(status);
    await userEvent.setup().click(button(name)!);
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(sent().url).toBe(`/api/staff/v1/cases/${CASE}/transitions`);
    expect(sent().body).toEqual({ event, expected_version: 4 });
  });

  it("blocks submission while records still need review", () => {
    show("UNDER_REVIEW", 2);
    expect(button("Submit for approval")!.disabled).toBe(true);
    expect(screen.getByText(/Resolve 2 records marked/)).toBeTruthy();
  });

  it("offers nothing once the case has moved past review", () => {
    show("AWAITING_APPROVAL");
    expect(screen.queryAllByRole("button")).toHaveLength(0);
  });

  it("explains a forbidden transition", async () => {
    postJson.mockImplementation(reply(403));
    show("UNDER_REVIEW");
    await userEvent.setup().click(button("Submit for approval")!);
    expect(await text("alert")).toBe("Your role can't do this.");
  });
});
