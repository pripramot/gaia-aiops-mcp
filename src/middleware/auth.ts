import type { Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

import type { TokenPayload, AuthenticatedRequest } from '../types/index.js';
import type { Role }                               from '../config/constants.js';
import { PERMISSIONS }                             from '../config/constants.js';
import { logger }                                  from '../utils/logger.js';

const JWT_SECRET = process.env['JWT_SECRET'] ?? 'CHANGE_ME_IMMEDIATELY';

/**
 * Verify the Authorization: Bearer <token> header.
 * On success, attaches `req.operator` (TokenPayload) and calls next().
 */
export function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authorization header missing' });
    return;
  }

  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET) as TokenPayload;
    req.operator = payload;
    next();
  } catch (err) {
    const message =
      err instanceof jwt.TokenExpiredError ? 'Token expired' : 'Invalid token';
    logger.warn('Auth failure', { message, ip: req.ip });
    res.status(401).json({ error: message });
  }
}

/**
 * RBAC gate.  Returns an Express middleware that rejects requests whose
 * `req.operator.role` is not listed in the PERMISSIONS map for `permission`.
 *
 * Usage:  router.get('/secret', authenticate, requirePermission('case:read'), handler)
 */
export function requirePermission(permission: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    const allowed: Role[] = PERMISSIONS[permission] ?? [];
    if (!allowed.includes(req.operator.role)) {
      logger.warn('RBAC denied', {
        badge:              req.operator.badge,
        role:               req.operator.role,
        requiredPermission: permission,
        path:               req.path,
      });
      res.status(403).json({ error: `Permission denied: requires '${permission}'` });
      return;
    }
    next();
  };
}
