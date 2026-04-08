import { Router }   from 'express';
import bcrypt        from 'bcryptjs';
import jwt           from 'jsonwebtoken';
import { z }         from 'zod';

import { pool }               from '../config/database.js';
import { validate }           from '../middleware/validate.js';
import { writeAuditLog }      from '../middleware/audit.js';
import { authenticate }       from '../middleware/auth.js';
import { logger }             from '../utils/logger.js';
import { JWT_EXPIRES_IN }     from '../config/constants.js';
import type { TokenPayload, AuthenticatedRequest } from '../types/index.js';

export const authRouter = Router();

const JWT_SECRET = process.env['JWT_SECRET'] ?? 'CHANGE_ME_IMMEDIATELY';

// ── Validation schemas ───────────────────────────────────────────────────────

const loginSchema = z.object({
  badgeNumber: z.string().min(3).max(50),
  password:    z.string().min(8).max(128),
});

// ── POST /api/auth/login ─────────────────────────────────────────────────────
authRouter.post('/login', validate(loginSchema), async (req, res) => {
  const { badgeNumber, password } = req.body as z.infer<typeof loginSchema>;

  const { rows } = await pool.query<{
    id:            string;
    badge_number:  string;
    full_name:     string;
    role:          string;
    password_hash: string;
    is_active:     boolean;
    failed_login:  number;
  }>(
    `SELECT id, badge_number, full_name, role, password_hash, is_active, failed_login
       FROM operators
      WHERE badge_number = $1
      LIMIT 1`,
    [badgeNumber],
  );

  const op = rows[0];

  // Always run bcrypt.compare to prevent timing-based user enumeration.
  // The dummy hash is a valid bcrypt hash so bcrypt takes the same time.
  const DUMMY_HASH = '$2b$12$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.';
  const match = await bcrypt.compare(password, op?.password_hash ?? DUMMY_HASH);

  if (!op || !match || !op.is_active) {
    if (op) {
      await pool.query(
        'UPDATE operators SET failed_login = failed_login + 1 WHERE id = $1',
        [op.id],
      );
    }
    await writeAuditLog({
      actionType:     'LOGIN_FAILURE',
      ipAddress:      req.ip,
      requestSummary: { badge: badgeNumber },
      responseStatus: 401,
    });
    res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    return;
  }

  if (op.failed_login >= 5) {
    res.status(423).json({ error: 'บัญชีถูกล็อก กรุณาติดต่อผู้ดูแลระบบ' });
    return;
  }

  const sessionId = crypto.randomUUID();

  const payload: TokenPayload = {
    sub:       op.id,
    badge:     op.badge_number,
    role:      op.role as TokenPayload['role'],
    sessionId,
  };

  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  } as jwt.SignOptions);

  // Reset consecutive failure counter and record last login
  await pool.query(
    'UPDATE operators SET last_login = NOW(), failed_login = 0 WHERE id = $1',
    [op.id],
  );

  await writeAuditLog({
    operatorId:     op.id,
    sessionId,
    actionType:     'LOGIN_SUCCESS',
    ipAddress:      req.ip,
    requestSummary: { badge: badgeNumber },
    responseStatus: 200,
  });

  logger.info('Login success', { badge: op.badge_number, role: op.role });

  res.json({
    token,
    operator: {
      id:          op.id,
      badgeNumber: op.badge_number,
      fullName:    op.full_name,
      role:        op.role,
    },
    expiresIn: JWT_EXPIRES_IN,
  });
});

// ── POST /api/auth/logout ────────────────────────────────────────────────────
authRouter.post(
  '/logout',
  authenticate as never,
  async (req, res) => {
    const op = (req as unknown as AuthenticatedRequest).operator;
    await writeAuditLog({
      operatorId:     op.sub,
      sessionId:      op.sessionId,
      actionType:     'LOGOUT',
      ipAddress:      req.ip,
      responseStatus: 200,
    });
    res.json({ message: 'ออกจากระบบเรียบร้อย' });
  },
);

// ── GET /api/auth/me ─────────────────────────────────────────────────────────
authRouter.get(
  '/me',
  authenticate as never,
  (req, res) => {
    const op = (req as unknown as AuthenticatedRequest).operator;
    res.json({ sub: op.sub, badge: op.badge, role: op.role });
  },
);
