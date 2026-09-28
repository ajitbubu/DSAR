/**
 * The only staff API mutations the browser may trigger through the BFF. Anything else is
 * refused before reaching the API, even with a valid session and CSRF token.
 */
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

export const STAFF_MUTATIONS: readonly RegExp[] = [
  new RegExp(`^/v1/cases/${UUID}/transitions$`),
  new RegExp(`^/v1/cases/${UUID}/matches/${UUID}/retention-decisions$`),
  new RegExp(`^/v1/cases/${UUID}/discovery/retry$`),
  /^\/v1\/legal-holds$/,
  new RegExp(`^/v1/legal-holds/${UUID}/release$`),
];

export function isAllowedStaffMutation(path: string): boolean {
  return STAFF_MUTATIONS.some((re) => re.test(path));
}
