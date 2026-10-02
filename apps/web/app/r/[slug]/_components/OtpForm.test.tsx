// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OtpForm } from "./OtpForm";

const push = vi.fn();
const postJson = vi.fn();

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/lib/client", () => ({
  useCsrfToken: () => "csrf-token",
  postJson: (...args: unknown[]) => postJson(...args),
}));

const codeInput = () => screen.getByLabelText("Verification code") as HTMLInputElement;
const alertText = async () => (await screen.findByRole("alert")).textContent;

async function submit(code: string) {
  const user = userEvent.setup();
  await user.type(codeInput(), code);
  await user.click(screen.getByRole("button", { name: "Verify" }));
  return user;
}

describe("OtpForm", () => {
  beforeEach(() => render(<OtpForm slug="acme" destinationHint="p•••@e•••.in" />));
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("keeps only digits and refuses anything but six of them, without calling the server", async () => {
    await submit("12a3");
    expect(codeInput().value).toBe("123");
    expect(await alertText()).toBe("Enter the 6-digit code.");
    expect(postJson).not.toHaveBeenCalled();
  });

  it("goes to the status page when the code is accepted", async () => {
    postJson.mockResolvedValue(new Response(null, { status: 200 }));
    await submit("123456");
    await waitFor(() => expect(push).toHaveBeenCalledWith("/r/acme/status"));
    expect(postJson).toHaveBeenCalledWith("/api/public/verify", "csrf-token", { code: "123456" });
  });

  it.each([
    [422, "That code isn't right"],
    [410, "This code has expired"],
    [409, "This code was already used"],
  ])("explains a %i", async (status, message) => {
    postJson.mockResolvedValue(new Response(null, { status }));
    await submit("123456");
    expect(await alertText()).toContain(message);
    expect(codeInput().disabled).toBe(false);
  });

  it("locks the form after too many attempts", async () => {
    postJson.mockResolvedValue(new Response(null, { status: 429 }));
    await submit("123456");
    expect(await alertText()).toContain("can't be verified");
    expect(codeInput().disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Send a new code" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("confirms a resent code", async () => {
    postJson.mockResolvedValue(new Response(null, { status: 202 }));
    await userEvent.setup().click(screen.getByRole("button", { name: "Send a new code" }));
    expect((await screen.findByRole("status")).textContent).toBe("We've sent a new code.");
  });
});
