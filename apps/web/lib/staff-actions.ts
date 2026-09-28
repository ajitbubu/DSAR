/**
 * The only staff API mutations the browser may trigger through the BFF. Anything else is
 * refused before reaching the API, even with a valid session and CSRF token.
 */
const UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

export const STAFF_MUTATIONS: readonly RegExp[] = [
  new RegExp(`^/v1/cases/${UUID}/transitions$`),
  new RegExp(`^/v1/cases/${UUID}/matches/${UUID}/retention-decisions$`),
  new RegExp(`^/v1/cases/${UUID}/discovery/retry$`),
  new RegExp(`^/v1/cases/${UUID}/approvals$`),
  new RegExp(`^/v1/cases/${UUID}/fulfilment-tasks/${UUID}/retry$`),
  /^\/v1\/legal-holds$/,
  new RegExp(`^/v1/legal-holds/${UUID}/release$`),
  new RegExp(`^/v1/cases/${UUID}/reconcile$`),
  /^\/v1\/audit\/verify$/,
  new RegExp(`^/v1/cases/${UUID}/disclosure/exports$`),
  new RegExp(`^/v1/cases/${UUID}/disclosure/exclusions$`),
  /^\/v1\/processing-register\/[a-z][a-z0-9_-]{1,39}$/,
];

export const STAFF_DOWNLOAD = new RegExp(`^/v1/cases/${UUID}/evidence/${UUID}/content$`);
export const STAFF_UPLOAD = new RegExp(`^/v1/cases/${UUID}/evidence$`);

export function isAllowedStaffMutation(path: string): boolean {
  return STAFF_MUTATIONS.some((re) => re.test(path));
}
