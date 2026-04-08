import { Router }   from 'express';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z }         from 'zod';

import { pool }          from '../config/database.js';
import { authenticate }  from '../middleware/auth.js';
import {
  buildEvidenceCanonical,
  hmacSign,
  hmacVerify,
} from '../utils/signature.js';
import { logger } from '../utils/logger.js';

export const mcpRouter = Router();

// ── MCP Tool definitions (shared between SSE handler and REST endpoint) ───────

/**
 * Register all GTSAlpha forensic tools onto an McpServer instance.
 * Called once per incoming SSE connection.
 */
export function registerMcpTools(server: McpServer, _sessionToken: string): void {

  // ── search_cases ────────────────────────────────────────────────────────────
  server.tool(
    'search_cases',
    'ค้นหาคดีในระบบ GTSAlpha Forensics',
    {
      status:  z.enum(['open', 'active', 'closed']).optional().describe('สถานะคดี'),
      keyword: z.string().optional().describe('ค้นหาจากชื่อหรือเลขคดี'),
      limit:   z.number().min(1).max(50).default(10),
    },
    async ({ status, keyword, limit }) => {
      const params:     unknown[] = [];
      const conditions: string[]  = [];

      if (status)  { params.push(status);  conditions.push(`c.status = $${params.length}`); }
      if (keyword) {
        params.push(`%${keyword}%`);
        conditions.push(
          `(c.case_number ILIKE $${params.length} OR c.title ILIKE $${params.length})`,
        );
      }

      params.push(limit);
      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

      const { rows } = await pool.query(
        `SELECT c.id, c.case_number, c.title, c.status, c.classification, c.created_at
           FROM cases c
           ${where}
           ORDER BY c.created_at DESC
           LIMIT $${params.length}`,
        params,
      );

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ cases: rows, total: rows.length }, null, 2),
        }],
      };
    },
  );

  // ── get_custody_chain ────────────────────────────────────────────────────────
  server.tool(
    'get_custody_chain',
    'ดู Chain of Custody ของพยานหลักฐาน เพื่อตรวจสอบความถูกต้องตาม ISO/IEC 27037',
    { evidenceId: z.string().uuid().describe('UUID ของพยานหลักฐาน') },
    async ({ evidenceId }) => {
      const { rows } = await pool.query(
        `SELECT c.*,
                f.full_name AS from_name,
                t.full_name AS to_name
           FROM custody_chain c
      LEFT JOIN operators f ON f.id = c.from_operator
      LEFT JOIN operators t ON t.id = c.to_operator
          WHERE c.evidence_id = $1
          ORDER BY c.sequence_num ASC`,
        [evidenceId],
      );

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ custody_chain: rows, total: rows.length }, null, 2),
        }],
      };
    },
  );

  // ── query_chronos_events ────────────────────────────────────────────────────
  server.tool(
    'query_chronos_events',
    'ดึงข้อมูล AI Events จากหน่วย WATCHER, INTERPRETER, PROPHET, HUNTER',
    {
      caseId:    z.string().uuid().optional(),
      unit:      z.enum(['WATCHER', 'INTERPRETER', 'PROPHET', 'HUNTER']).optional(),
      eventType: z.string().optional(),
      limit:     z.number().min(1).max(100).default(20),
    },
    async ({ caseId, unit, eventType, limit }) => {
      const params:     unknown[] = [];
      const conditions: string[]  = [];

      if (caseId)    { params.push(caseId);    conditions.push(`case_id = $${params.length}`); }
      if (unit)      { params.push(unit);      conditions.push(`unit = $${params.length}`); }
      if (eventType) { params.push(eventType); conditions.push(`event_type = $${params.length}`); }

      params.push(limit);
      const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

      const { rows } = await pool.query(
        `SELECT * FROM chronos_events
         ${where}
         ORDER BY created_at DESC
         LIMIT $${params.length}`,
        params,
      );

      return {
        content: [{ type: 'text', text: JSON.stringify({ events: rows }, null, 2) }],
      };
    },
  );

  // ── validate_evidence_hash ──────────────────────────────────────────────────
  server.tool(
    'validate_evidence_hash',
    'ตรวจสอบความสมบูรณ์ของพยานหลักฐาน (Integrity Check) ด้วย HMAC-SHA256',
    { evidenceId: z.string().uuid() },
    async ({ evidenceId }) => {
      const { rows: [ev] } = await pool.query<{
        evidence_number: string;
        sha256_hash:     string;
        hmac_signature:  string;
        case_id:         string;
        collected_at:    Date;
      }>(
        'SELECT evidence_number, sha256_hash, hmac_signature, case_id, collected_at FROM evidence WHERE id = $1',
        [evidenceId],
      );

      if (!ev) {
        return {
          content: [{ type: 'text', text: '❌ ไม่พบพยานหลักฐาน' }],
          isError: true,
        };
      }

      const canonical = buildEvidenceCanonical({
        sha256Hash:     ev.sha256_hash,
        evidenceNumber: ev.evidence_number,
        caseId:         ev.case_id,
        collectedAt:    ev.collected_at.toISOString(),
      });

      const isValid = hmacVerify(canonical, ev.hmac_signature);

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            evidenceNumber: ev.evidence_number,
            sha256Hash:     ev.sha256_hash,
            isIntact:       isValid,
            message: isValid
              ? '✅ หลักฐานไม่ถูกแก้ไข — Integrity verified'
              : '⚠️ Possible tamper detected',
          }, null, 2),
        }],
      };
    },
  );

  // ── get_case_timeline ───────────────────────────────────────────────────────
  server.tool(
    'get_case_timeline',
    'สร้าง Timeline ของเหตุการณ์ทั้งหมดในคดี เรียงตามเวลา',
    { caseId: z.string().uuid() },
    async ({ caseId }) => {
      const [{ rows: evidenceRows }, { rows: eventRows }] = await Promise.all([
        pool.query(
          `SELECT id, evidence_number, evidence_type, file_name,
                  collected_at AS ts, 'evidence_ingest' AS event_category
             FROM evidence WHERE case_id = $1`,
          [caseId],
        ),
        pool.query(
          `SELECT id, event_type, unit, confidence_score,
                  created_at AS ts, 'chronos_event' AS event_category
             FROM chronos_events WHERE case_id = $1`,
          [caseId],
        ),
      ]);

      const timeline = [...evidenceRows, ...eventRows].sort(
        (a, b) =>
          new Date(a['ts'] as string).getTime() -
          new Date(b['ts'] as string).getTime(),
      );

      return {
        content: [{
          type: 'text',
          text: JSON.stringify({ timeline, total: timeline.length }, null, 2),
        }],
      };
    },
  );

  logger.info('MCP tools registered', {
    tools: ['search_cases', 'get_custody_chain', 'query_chronos_events',
            'validate_evidence_hash', 'get_case_timeline'],
  });
}

// ── REST: GET /api/mcp/tools  — list available tools (no auth needed) ────────
mcpRouter.get('/tools', authenticate as never, (_req, res) => {
  res.json({
    tools: [
      'search_cases',
      'get_custody_chain',
      'query_chronos_events',
      'validate_evidence_hash',
      'get_case_timeline',
    ],
    count: 5,
  });
});
