export type ProductActionScope = "device" | "project";

/**
 * Canonical action-scope boundary used by Product grants.
 *
 * Device-scoped actions operate on the linked device itself and must not need a
 * synthetic project id. Project-scoped actions remain bound to an explicit
 * registered project grant.
 *
 * Keep these sets explicit: adding a new remote Computer or App Intelligence
 * capability requires a reviewed scope decision instead of inheriting authority
 * from a prefix match. Domain grant profiles must use their own subset, never
 * the DEVICE_SCOPED_ACTIONS union.
 */
export const PROJECT_BROWSER_ACTIONS = new Set<string>([
  "browser.click",
  "browser.list",
  "browser.navigate",
  "browser.screenshot",
  "browser.snapshot",
  "browser.start",
  "browser.status",
  "browser.stop",
  "browser.type",
]);

export const APP_INTELLIGENCE_DEVICE_ACTIONS = new Set<string>([
  "intelligence.app_catalog",
  "intelligence.app_detail",
]);

export const COMPUTER_DEVICE_ACTIONS = new Set<string>([
  "computer.access_status",
  "computer.active_window",
  "computer.click",
  "computer.clipboard_read",
  "computer.clipboard_write",
  "computer.directory_create",
  "computer.directory_list",
  "computer.drag",
  "computer.file_stat",
  "computer.focus_window",
  "computer.hotkey",
  "computer.launch_app",
  "computer.mouse_move",
  "computer.path_move",
  "computer.path_remove",
  "computer.processes",
  "computer.screen_info",
  "computer.screenshot",
  "computer.scroll",
  "computer.search",
  "computer.terminate_process",
  "computer.text_patch",
  "computer.text_read",
  "computer.text_write",
  "computer.type",
  "computer.windows",
]);

export const DEVICE_SCOPED_ACTIONS = new Set<string>([
  ...COMPUTER_DEVICE_ACTIONS,
  ...APP_INTELLIGENCE_DEVICE_ACTIONS,
]);



export function isDeviceScopedAction(action: string): boolean {
  return DEVICE_SCOPED_ACTIONS.has(action);
}

export function productActionScope(
  action: string,
  projectScopedActions: ReadonlySet<string>,
): ProductActionScope {
  if (DEVICE_SCOPED_ACTIONS.has(action)) return "device";
  return projectScopedActions.has(action) ? "project" : "device";
}

/**
 * Enforces the canonical project binding shape before grant resolution.
 *
 * Device actions must use project=null. Project actions must provide a concrete
 * project. This prevents fake project ids from being used to model device
 * authority and prevents a project action from silently degrading to a device
 * grant.
 */
export function projectBindingMatchesScope(
  action: string,
  project: string | null,
  projectScopedActions: ReadonlySet<string>,
): boolean {
  const scope = productActionScope(action, projectScopedActions);
  return scope === "device" ? project === null : project !== null;
}
