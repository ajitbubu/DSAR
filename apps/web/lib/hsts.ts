/** HSTS is only meaningful (and only sent) when the app is served over https. */
export function hstsHeader(appOrigin: string | undefined): string | null {
  return appOrigin?.startsWith("https://") ? "max-age=31536000; includeSubDomains" : null;
}
