// ── RBAC Roles ───────────────────────────────────────────────────────────────
export const ROLES = {
  SUPER_ADMIN:  'super_admin',
  C3_COMMANDER: 'c3_commander',
  ANALYST:      'analyst',
  VIEWER:       'viewer',
} as const;

export type Role = typeof ROLES[keyof typeof ROLES];

// ── Permission matrix ────────────────────────────────────────────────────────
// Each string key maps to the roles that are allowed to perform that action.
export const PERMISSIONS: Record<string, Role[]> = {
  'case:create':         [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER],
  'case:read':           [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER, ROLES.ANALYST, ROLES.VIEWER],
  'case:update':         [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER],
  'case:close':          [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER],

  'evidence:ingest':     [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER, ROLES.ANALYST],
  'evidence:read':       [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER, ROLES.ANALYST, ROLES.VIEWER],
  'evidence:face_match': [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER],

  'chronos:log':         [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER, ROLES.ANALYST],
  'chronos:read':        [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER, ROLES.ANALYST, ROLES.VIEWER],

  'report:create':       [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER, ROLES.ANALYST],
  'report:court_ready':  [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER],

  'operator:manage':     [ROLES.SUPER_ADMIN],
  'audit:read':          [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER],

  'mcp:session:create':  [ROLES.SUPER_ADMIN, ROLES.C3_COMMANDER, ROLES.ANALYST],
};

// ── JWT ──────────────────────────────────────────────────────────────────────
export const JWT_EXPIRES_IN  = process.env['JWT_EXPIRES_IN']  ?? '8h';
export const REFRESH_EXPIRES = process.env['REFRESH_EXPIRES'] ?? '7d';

// ── MCP Tools ────────────────────────────────────────────────────────────────
export const MCP_TOOLS = [
  'search_cases',
  'get_custody_chain',
  'query_chronos_events',
  'validate_evidence_hash',
  'get_case_timeline',
] as const;

export type McpTool = typeof MCP_TOOLS[number];
