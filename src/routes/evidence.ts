import { Router }             from 'express';
import { z }                  from 'zod';

import { pool }               from '../config/database.js';
import { authenticate,
         requirePermission }  from '../middleware/auth.js';
import { validate }           from '../middleware/validate.js';
import { writeAuditLog }      from '../middleware/audit.js';
import {
  buildEvidenceCanonical,
  hmacSign,
  hmacVerify,
  custodyRecordHash,
} from '../utils/signature.js';
import type { AuthenticatedRequest } from '../types/index.js';

export const evidenceRouter = Router();

evidenceRouter.use(authenticate as never);

// ── Validation schemas ────────────────────────────────────────────────────────

const ingestSchema = z.object({
  caseId:            z.string().uuid(),
  evidenceType:      z.enum([
    'image', 'video', 'audio', 'document',
    'biometric', 'network_log', 'device_image',
    'location_data', 'social_media', 'other',
  ]),
  fileName:          z.string().min(1).max(500),
  fileSize:          z.number().positive().optional(),
  mimeType:          z.string().max(100).optional(),
  storagePath:       z.string().min(1).max(1000),
  sha256Hash:        z
    .string()
    .length(64)
    .regex(/^[a-f0-9]+$/, 'sha256Hash must be 64 lower-case hex characters'),
  sourceDevice:      z.string().max(200).optional(),
  sourceIp:          z.string().ip().optional(),
  acquisitionMethod: z.string().max(100).optional(),
  collectedAt:       z.string().datetime(),
  metadata:          z.record(z.unknown()).optional(),
});

// ── GET /api/evidence/case/:caseId ───────────────────────────────────────────
evidenceRouter.get(
  '/case/:caseId',
  requirePermission('evidence:read') as never,
  async (req, res) => {
    const { rows } = await pool.query(
      `SELECT e.*, o.full_name AS collected_by_name
         FROM evidence e
         JOIN operators o ON o.id = e.collected_by
        WHERE e.case_id = $1
        ORDER BY e.created_at DESC`,
      [req.params['caseId']],
    );
    res.json({ evidence: rows, total: rows.length });
  },
);

// ── POST /api/evidence  (ingest) ─────────────────────────────────────────────
evidenceRouter.post(
  '/',
  requirePermission('evidence:ingest') as never,
  validate(ingestSchema),
  async (req, res) => {
    const op   = (req as AuthenticatedRequest).operator;
    const body = req.body as z.infer<typeof ingestSchema>;

    // Evidence number:  EV-YYYYMMDD-<8-char UUID prefix>
    const datePart       = new Date().toISOString().slice(0, 10).replace(/-/g, '');
    const evidenceNumber = `EV-${datePart}-${crypto.randomUUID().slice(0, 8).toUpperCase()}`;

    // HMAC-SHA256 signature — proves the record was created by this server
    const canonical      = buildEvidenceCanonical({
      sha256Hash:     body.sha256Hash,
      evidenceNumber,
      caseId:         body.caseId,
      collectedAt:    body.collectedAt,
    });
    const hmacSignature  = hmacSign(canonical);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const { rows: [ev] } = await client.query<{
        id:          string;
        created_at:  Date;
        sha256_hash: string;
        case_id:     string;
        [key: string]: unknown;
      }>(
        `INSERT INTO evidence
           (evidence_number, case_id, evidence_type, file_name, file_size, mime_type,
            storage_path, sha256_hash, hmac_signature, source_device, source_ip,
            acquisition_method, collected_by, collected_at, metadata)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         RETURNING *`,
        [
          evidenceNumber, body.caseId, body.evidenceType,
          body.fileName,  body.fileSize ?? null, body.mimeType ?? null,
          body.storagePath, body.sha256Hash, hmacSignature,
          body.sourceDevice ?? null, body.sourceIp ?? null,
          body.acquisitionMethod ?? null, op.sub,
          body.collectedAt, JSON.stringify(body.metadata ?? {}),
        ],
      );

      // First Chain-of-Custody entry (sequence_num = 1, action = 'received')
      const occurredAt = ev.created_at.toISOString();
      const firstHash  = custodyRecordHash(
        '0'.repeat(64), ev.id, 'received', op.sub, occurredAt,
      );
      await client.query(
        `INSERT INTO custody_chain
           (evidence_id, sequence_num, action, to_operator, hash_at_time, record_hash, occurred_at)
         VALUES ($1, 1, 'received', $2, $3, $4, $5)`,
        [ev.id, op.sub, ev.sha256_hash, firstHash, ev.created_at],
      );

      await client.query('COMMIT');

      await writeAuditLog({
        operatorId:     op.sub,
        sessionId:      op.sessionId,
        actionType:     'EVIDENCE_INGEST',
        resourceType:   'evidence',
        resourceId:     ev.id,
        ipAddress:      req.ip,
        requestSummary: {
          evidenceNumber,
          type: body.evidenceType,
          sha256Hash: body.sha256Hash,
        },
        responseStatus: 201,
      });

      res.status(201).json({ ...ev, hmacVerified: true });
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  },
);

// ── GET /api/evidence/:id/custody ────────────────────────────────────────────
evidenceRouter.get(
  '/:id/custody',
  requirePermission('evidence:read') as never,
  async (req, res) => {
    const { rows: [ev] } = await pool.query(
      'SELECT * FROM evidence WHERE id = $1',
      [req.params['id']],
    );
    if (!ev) {
      res.status(404).json({ error: 'ไม่พบหลักฐาน' });
      return;
    }

    const { rows: chain } = await pool.query(
      `SELECT c.*,
              f.full_name AS from_name,
              t.full_name AS to_name
         FROM custody_chain c
    LEFT JOIN operators f ON f.id = c.from_operator
    LEFT JOIN operators t ON t.id = c.to_operator
        WHERE c.evidence_id = $1
        ORDER BY c.sequence_num ASC`,
      [req.params['id']],
    );

    res.json({
      evidence:        ev,
      custody_chain:   chain,
      total_transfers: chain.length,
    });
  },
);

// ── POST /api/evidence/:id/validate ─────────────────────────────────────────
evidenceRouter.post(
  '/:id/validate',
  requirePermission('evidence:read') as never,
  async (req, res) => {
    const op = (req as unknown as AuthenticatedRequest).operator;

    const { rows: [ev] } = await pool.query<{
      id:                string;
      evidence_number:   string;
      sha256_hash:       string;
      hmac_signature:    string;
      case_id:           string;
      collected_at:      Date;
      is_tamper_detected: boolean;
    }>(
      'SELECT * FROM evidence WHERE id = $1',
      [req.params['id']],
    );

    if (!ev) {
      res.status(404).json({ error: 'ไม่พบหลักฐาน' });
      return;
    }

    const canonical = buildEvidenceCanonical({
      sha256Hash:     ev.sha256_hash,
      evidenceNumber: ev.evidence_number,
      caseId:         ev.case_id,
      collectedAt:    ev.collected_at.toISOString(),
    });

    const isValid = hmacVerify(canonical, ev.hmac_signature);

    // Flag tamper in DB if newly detected
    if (!isValid && !ev.is_tamper_detected) {
      await pool.query(
        'UPDATE evidence SET is_tamper_detected = TRUE WHERE id = $1',
        [ev.id],
      );
      await writeAuditLog({
        operatorId:   op.sub,
        actionType:   'EVIDENCE_TAMPER_DETECTED',
        resourceType: 'evidence',
        resourceId:   ev.id,
        ipAddress:    req.ip,
        responseStatus: 200,
      });
    }

    res.json({
      evidenceNumber:  ev.evidence_number,
      sha256Hash:      ev.sha256_hash,
      isIntact:        isValid,
      isTamperDetected: !isValid,
      message: isValid
        ? '✅ หลักฐานไม่ถูกแก้ไข — Integrity verified'
        : '⚠️ พบความผิดปกติ — Possible tamper detected',
    });
  },
);
