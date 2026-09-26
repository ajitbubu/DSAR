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
  return fetch(`${serverConfig.apiBaseUrl}${path}`, {
    method: init.method ?? "GET",
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
    cache: "no-store",
  });
}
