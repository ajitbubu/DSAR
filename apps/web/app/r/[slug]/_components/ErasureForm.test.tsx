// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ErasureForm } from "./ErasureForm";

const push = vi.fn();
const postJson = vi.fn();
let csrf: string | null = "csrf-token";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/lib/client", () => ({
  useCsrfToken: () => csrf,
  postJson: (...args: unknown[]) => postJson(...args),
}));

function response(status: number, body: unknown = {}, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

async function fillValid() {
  const user = userEvent.setup();
  await user.type(screen.getByLabelText("Full name"), "Priya Sharma");
  await user.type(screen.getByLabelText("Email address"), "priya.sharma@example.in");
  await user.click(screen.getByLabelText(/I agree/));
  return user;
}

describe("ErasureForm", () => {
  beforeEach(() => {
    csrf = "csrf-token";
    render(<ErasureForm slug="acme" />);
  });
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("shows field errors and sends nothing when required fields are empty", async () => {
    await userEvent.setup().click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByLabelText("Full name").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByLabelText(/I agree/).getAttribute("aria-invalid")).toBe("true");
    expect(postJson).not.toHaveBeenCalled();
  });

  it("switches the contact field to a mobile number with an E.164 hint", async () => {
    await userEvent.setup().click(screen.getByLabelText("Mobile (SMS)"));
    expect(screen.getByLabelText("Mobile number").getAttribute("type")).toBe("tel");
    expect(screen.getByText(/Include the country code/)).toBeTruthy();
  });

  it("posts the request with the CSRF token and goes to the verify step on 202", async () => {
    postJson.mockResolvedValue(response(202));
    const user = await fillValid();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await waitFor(() => expect(push).toHaveBeenCalledWith("/r/acme/verify"));
    const [url, token, body] = postJson.mock.calls[0] ?? [];
    expect([url, token]).toEqual(["/api/public/requests", "csrf-token"]);
    expect(body).toMatchObject({ intakeSlug: "acme", contact: { channel: "EMAIL" } });
  });

  it("explains a rate limit using Retry-After", async () => {
    postJson.mockResolvedValue(response(429, {}, { "retry-after": "120" }));
    const user = await fillValid();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Too many attempts. Try again in about 2 minutes.");
    expect(push).not.toHaveBeenCalled();
  });

  it("maps a 422 back onto the field without echoing server detail", async () => {
    postJson.mockResolvedValue(
      response(422, { errors: [{ loc: ["body", "contact"], msg: "internal detail" }] }),
    );
    const user = await fillValid();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Check the highlighted fields");
    expect(screen.getByLabelText("Email address").getAttribute("aria-invalid")).toBe("true");
    expect(screen.queryByText("internal detail")).toBeNull();
  });

  it("reports a network failure", async () => {
    postJson.mockRejectedValue(new TypeError("Failed to fetch"));
    const user = await fillValid();
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect((await screen.findByRole("alert")).textContent).toContain("couldn't reach the server");
  });
});

describe("ErasureForm before the CSRF token arrives", () => {
  afterEach(() => cleanup());

  it("keeps the submit button disabled", () => {
    csrf = null;
    render(<ErasureForm slug="acme" />);
    expect((screen.getByRole("button", { name: "Continue" }) as HTMLButtonElement).disabled).toBe(true);
  });
});
