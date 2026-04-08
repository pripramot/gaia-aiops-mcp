import { Router }          from 'express';
import { z }               from 'zod';

import { pool }            from '../config/database.js';
import { authenticate,
         requirePermission } from '../middleware/auth.js';
import { validate }        from '../middleware/validate.js';
import { writeAuditLog }   from '../middleware/audit.js';
import { sha256 }          from '../utils/signature.js';
import type { AuthenticatedRequest } from '../types/index.js';

export const casesRouter = Router();

// All case routes require a valid JWT
casesRouter.use(authenticate as never);

// ── Validation schemas ───────────────────────────────────────────────────────

const createCaseSchema = z.object({
  caseNumber:     z.string().min(5).max(50).regex(
    /^[A-Z0-9\-]+$/,
    'เลขคดีใช้ได้เฉพาะตัวพิมพ์ใหญ่ A-Z, 0-9 และ -',
  ),
  title:          z.string().min(5).max(500),
  classification: z.enum(['public', 'restricted', 'confidential', 'secret'])
                    .default('confidential'),
  description:    z.string().max(2000).optional(),
  metadata:       z.record(z.unknown()).optional(),
});

// ── GET /api/cases ────────────────────────────────────────────────────────────
casesRouter.get(
  '/',
  requirePermission('case:read') as never,
  async (_req, res) => {
    const { rows } = await pool.query(
      `SELECT c.id, c.case_number, c.title, c.status, c.classification,
              c.created_at, c.closed_at,
              o.full_name              AS created_by_name,
              COUNT(DISTINCT e.id)     AS evidence_count
         FROM cases c
         JOIN operators o ON o.id = c.created_by
    LEFT JOIN evidence e ON e.case_id = c.id
        WHERE c.status != 'archived'
     GROUP BY c.id, o.full_name
     ORDER BY c.created_at DESC`,
    );
    res.json({ cases: rows, total: rows.length });
  },
);

// ── GET /api/cases/:id ────────────────────────────────────────────────────────
casesRouter.get(
  '/:id',
  requirePermission('case:read') as never,
  async (req, res) => {
    const { rows } = await pool.query(
      `SELECT c.*, o.full_name AS created_by_name
         FROM cases c
         JOIN operators o ON o.id = c.created_by
        WHERE c.id = $1 OR c.case_number = $1`,
      [req.params['id']],
    );
    if (!rows[0]) {
      res.status(404).json({ error: 'ไม่พบคดี' });
      return;
    }
    res.json(rows[0]);
  },
);

// ── POST /api/cases ───────────────────────────────────────────────────────────
casesRouter.post(
  '/',
  requirePermission('case:create') as never,
  validate(createCaseSchema),
  async (req, res) => {
    const op   = (req as AuthenticatedRequest).operator;
    const body = req.body as z.infer<typeof createCaseSchema>;

    const now           = new Date().toISOString();
    const integrityHash = sha256(`${body.caseNumber}|${body.title}|${op.sub}|${now}`);

    const { rows } = await pool.query(
      `INSERT INTO cases
         (case_number, title, classification, description, created_by, metadata, integrity_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        body.caseNumber,
        body.title,
        body.classification,
        body.description ?? null,
        op.sub,
        JSON.stringify(body.metadata ?? {}),
        integrityHash,
      ],
    );

    await writeAuditLog({
      operatorId:     op.sub,
      sessionId:      op.sessionId,
      actionType:     'CASE_CREATE',
      resourceType:   'case',
      resourceId:     rows[0].id as string,
      caseNumber:     body.caseNumber,
      ipAddress:      req.ip,
      requestSummary: { caseNumber: body.caseNumber, title: body.title },
      responseStatus: 201,
    });

    res.status(201).json(rows[0]);
  },
);

// ── PATCH /api/cases/:id/close ────────────────────────────────────────────────
casesRouter.patch(
  '/:id/close',
  requirePermission('case:close') as never,
  async (req, res) => {
    const op = (req as unknown as AuthenticatedRequest).operator;

    const { rows } = await pool.query(
      `UPDATE cases
          SET status = 'closed', closed_at = NOW()
        WHERE id = $1 AND status NOT IN ('closed','archived')
        RETURNING *`,
      [req.params['id']],
    );

    if (!rows[0]) {
      res.status(404).json({ error: 'ไม่พบคดี หรือคดีถูกปิดแล้ว' });
      return;
    }

    await writeAuditLog({
      operatorId:   op.sub,
      sessionId:    op.sessionId,
      actionType:   'CASE_CLOSE',
      resourceType: 'case',
      resourceId:   rows[0].id as string,
      caseNumber:   rows[0].case_number as string,
      ipAddress:    req.ip,
      responseStatus: 200,
    });

    res.json(rows[0]);
  },
);
