import type { Response, NextFunction } from 'express';

import type { AuthenticatedRequest } from '../types/index.js';
import { pool }                      from '../config/database.js';
import { chainHash }                 from '../utils/signature.js';
import { logger }                    from '../utils/logger.js';

export interface AuditParams {
  operatorId?:     string;
  sessionId?:      string;
  actionType:      string;
  resourceType?:   string;
  resourceId?:     string;
  caseNumber?:     string;
  ipAddress?:      string;
  userAgent?:      string;
  requestSummary?: Record<string, unknown>;
  responseStatus?: number;
}

/**
 * Write a single row to the immutable audit_log table.
 * The row carries a linked-hash chain so any gap or modification is detectable.
 *
 * This function never throws — audit failures are logged but must not
 * break the request pipeline.
 */
export async function writeAuditLog(params: AuditParams): Promise<void> {
  try {
    // Fetch the latest hash to extend the chain
    const { rows } = await pool.query<{ integrity_hash: string }>(
      'SELECT integrity_hash FROM audit_log ORDER BY id DESC LIMIT 1',
    );
    const prevHash = rows[0]?.integrity_hash ?? '0'.repeat(64);
    const now      = new Date().toISOString();

    const integrityHash = chainHash(
      prevHash,
      params.operatorId ?? 'system',
      params.actionType,
      now,
    );

    await pool.query(
      `INSERT INTO audit_log
         (operator_id, session_id, action_type, resource_type, resource_id,
          case_number, ip_address, user_agent, request_summary,
          response_status, prev_hash, integrity_hash, occurred_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        params.operatorId     ?? null,
        params.sessionId      ?? null,
        params.actionType,
        params.resourceType   ?? null,
        params.resourceId     ?? null,
        params.caseNumber     ?? null,
        params.ipAddress      ?? null,
        params.userAgent      ?? null,
        JSON.stringify(params.requestSummary ?? {}),
        params.responseStatus ?? null,
        prevHash,
        integrityHash,
        now,
      ],
    );
  } catch (err) {
    logger.error('Failed to write audit log', { err });
  }
}

/**
 * Express middleware that hooks `res.json()` to fire-and-forget an audit entry
 * for every API response.  Attaches after authentication so `req.operator` is
 * available where the route is protected.
 */
export function auditMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): void {
  const originalJson = res.json.bind(res) as (body?: unknown) => Response;

  res.json = (body?: unknown): Response => {
    void writeAuditLog({
      operatorId:     req.operator?.sub,
      sessionId:      req.operator?.sessionId,
      actionType:     `${req.method}:${req.path}`,
      ipAddress:      req.ip,
      userAgent:      req.headers['user-agent'],
      requestSummary: {
        method: req.method,
        path:   req.path,
        query:  req.query,
      },
      responseStatus: res.statusCode,
    });
    return originalJson(body);
  };

  next();
}
