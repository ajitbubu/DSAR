import "server-only";
import { serverConfig } from "./config";

/** Calls the internal API as the BFF. Only server code can use this module. */
export async function callApi(
  path: string,
  init: { method?: string; body?: unknown; clientIp?: string; dpSession?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = {
    "X-Internal-Auth": serverConfig.bffSharedSecret,
    Accept: "application/json",
  };
  if (init.clientIp) headers["X-Client-IP"] = init.clientIp;
  if (init.dpSession) headers["X-DP-Session"] = init.dpSession;
  if (init.body !== undefined) headers["Content-Type"] = "application/json";
  const method = init.method ?? "GET";
  const send = () => fetch(`${serverConfig.apiBaseUrl}${path}`, {
    method,
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    cache: "no-store",
  });
  try {
    return await send();
  } catch (err) {
    // A pooled keep-alive connection the API already closed. Retrying is safe only for
    // reads; a POST may have taken effect, so it's never retried.
    if (method === "GET" && isDroppedSocket(err)) return send();
    throw err;
  }
}

export function isDroppedSocket(err: unknown): boolean {
  const cause = (err as { cause?: { code?: string } } | null)?.cause;
  return err instanceof TypeError && (cause?.code === "UND_ERR_SOCKET" || cause?.code === "ECONNRESET");
}
