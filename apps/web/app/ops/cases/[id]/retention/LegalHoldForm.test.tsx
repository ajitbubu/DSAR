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

import { LegalHoldForm } from "./LegalHoldForm";

async function place(status: number) {
  postJson.mockImplementation(reply(status));
  render(<LegalHoldForm caseId={CASE} />);
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Matter reference"), "  LIT-2026-014 ");
  await user.type(screen.getByLabelText("Reason"), " Pending litigation hold. ");
  await user.click(screen.getByRole("button", { name: "Place legal hold" }));
  return user;
}

describe("LegalHoldForm", () => {
  it("defaults to every request from the person and sends trimmed values", async () => {
    await place(201);
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(sent().url).toBe("/api/staff/v1/legal-holds");
    expect(sent().body).toEqual({ scope: "DATA_PRINCIPAL", case_id: CASE,
      matter_ref: "LIT-2026-014", reason: "Pending litigation hold." });
    expect(await text("status")).toContain("Legal hold placed");
    expect((screen.getByLabelText("Matter reference") as HTMLInputElement).value).toBe("");
  });

  it("tells a role without permission that it can't place holds", async () => {
    await place(403);
    expect(await text("status")).toBe("Your role can't place legal holds.");
    expect(refresh).not.toHaveBeenCalled();
  });

  it("explains a rejected hold and keeps what was typed", async () => {
    await place(422);
    expect(await text("status")).toContain("Check the matter reference");
    expect((screen.getByLabelText("Matter reference") as HTMLInputElement).value).toBe("  LIT-2026-014 ");
  });
});
