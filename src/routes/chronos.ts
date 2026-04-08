import { Router }              from 'express';
import { z }                   from 'zod';

import { pool }                from '../config/database.js';
import { authenticate,
         requirePermission }   from '../middleware/auth.js';
import { validate }            from '../middleware/validate.js';
import { writeAuditLog }       from '../middleware/audit.js';
import { sha256 }              from '../utils/signature.js';
import type { AuthenticatedRequest } from '../types/index.js';

export const chronosRouter = Router();

chronosRouter.use(authenticate as never);

// ── Validation schemas ────────────────────────────────────────────────────────

const eventSchema = z.object({
  caseId:          z.string().uuid().optional(),
  evidenceId:      z.string().uuid().optional(),
  eventType:       z.enum([
    'face_detection', 'face_match', 'vehicle_detection',
    'ocr_read', 'lpr_read', 'location_track',
    'nlp_intent', 'nlp_sentiment',
    'path_prediction', 'osint_hit', 'object_detection',
  ]),
  unit:            z.enum(['WATCHER', 'INTERPRETER', 'PROPHET', 'HUNTER']),
  modelUsed:       z.string().max(100).optional(),
  confidenceScore: z.number().min(0).max(1).optional(),
  rawData:         z.record(z.unknown()),
  processedData:   z.record(z.unknown()).optional(),
  locationLat:     z.number().min(-90).max(90).optional(),
  locationLon:     z.number().min(-180).max(180).optional(),
  frameTimestamp:  z.string().datetime().optional(),
  sourceDevice:    z.string().max(200).optional(),
});

// ── POST /api/chronos/events ─────────────────────────────────────────────────
chronosRouter.post(
  '/events',
  requirePermission('chronos:log') as never,
  validate(eventSchema),
  async (req, res) => {
    const op   = (req as AuthenticatedRequest).operator;
    const body = req.body as z.infer<typeof eventSchema>;

    // Hash raw_data + timestamp to prove what data the AI unit processed
    const eventHash = sha256(
      JSON.stringify(body.rawData) + new Date().toISOString(),
    );

    const { rows: [event] } = await pool.query(
      `INSERT INTO chronos_events
         (case_id, evidence_id, event_type, unit, model_used, confidence_score,
          raw_data, processed_data, location_lat, location_lon,
          frame_timestamp, source_device, operator_id, sha256_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
       RETURNING *`,
      [
        body.caseId          ?? null,
        body.evidenceId      ?? null,
        body.eventType,
        body.unit,
        body.modelUsed       ?? null,
        body.confidenceScore ?? null,
        JSON.stringify(body.rawData),
        JSON.stringify(body.processedData ?? {}),
        body.locationLat     ?? null,
        body.locationLon     ?? null,
        body.frameTimestamp  ?? null,
        body.sourceDevice    ?? null,
        op.sub,
        eventHash,
      ],
    );

    await writeAuditLog({
      operatorId:     op.sub,
      sessionId:      op.sessionId,
      actionType:     `CHRONOS_${body.unit}_${body.eventType.toUpperCase()}`,
      resourceType:   'chronos_event',
      resourceId:     event.id as string,
      ipAddress:      req.ip,
      requestSummary: {
        unit:            body.unit,
        eventType:       body.eventType,
        confidenceScore: body.confidenceScore,
      },
      responseStatus: 201,
    });

    res.status(201).json(event);
  },
);

// ── GET /api/chronos/events ──────────────────────────────────────────────────
chronosRouter.get(
  '/events',
  requirePermission('chronos:read') as never,
  async (req, res) => {
    const { caseId, unit, eventType } = req.query as Record<string, string | undefined>;
    const limit  = Math.min(Number(req.query['limit']  ?? 50),  200);
    const offset = Math.max(Number(req.query['offset'] ?? 0), 0);

    const params:     unknown[] = [];
    const conditions: string[]  = [];

    if (caseId)    { params.push(caseId);    conditions.push(`ce.case_id = $${params.length}`); }
    if (unit)      { params.push(unit);      conditions.push(`ce.unit = $${params.length}`); }
    if (eventType) { params.push(eventType); conditions.push(`ce.event_type = $${params.length}`); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    params.push(limit, offset);

    const { rows } = await pool.query(
      `SELECT ce.*, o.full_name AS operator_name
         FROM chronos_events ce
         JOIN operators o ON o.id = ce.operator_id
         ${where}
         ORDER BY ce.created_at DESC
         LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params,
    );

    res.json({ events: rows, total: rows.length });
  },
);
