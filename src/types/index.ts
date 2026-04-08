import type { Role } from '../config/constants.js';
import type { Request } from 'express';

// ── JWT Token ────────────────────────────────────────────────────────────────
export interface TokenPayload {
  sub: string;        // operator UUID
  badge: string;
  role: Role;
  sessionId: string;
  iat?: number;
  exp?: number;
}

// ── Express augmentation ─────────────────────────────────────────────────────
export interface AuthenticatedRequest extends Request {
  operator: TokenPayload;
}

// ── Evidence ─────────────────────────────────────────────────────────────────
export interface EvidenceIngestBody {
  caseId: string;
  evidenceType: string;
  fileName: string;
  fileSize?: number;
  mimeType?: string;
  storagePath: string;
  sha256Hash: string;
  sourceDevice?: string;
  sourceIp?: string;
  acquisitionMethod?: string;
  collectedAt: string;
  metadata?: Record<string, unknown>;
}

// ── Chronos Event ────────────────────────────────────────────────────────────
export interface ChronosEventBody {
  caseId?: string;
  evidenceId?: string;
  eventType: string;
  unit: string;
  modelUsed?: string;
  confidenceScore?: number;
  rawData: Record<string, unknown>;
  processedData?: Record<string, unknown>;
  locationLat?: number;
  locationLon?: number;
  frameTimestamp?: string;
  sourceDevice?: string;
}

// ── DB Row shapes ─────────────────────────────────────────────────────────────
export interface OperatorRow {
  id: string;
  badge_number: string;
  full_name: string;
  role: string;
  department: string | null;
  password_hash: string;
  is_active: boolean;
  failed_login: number;
  last_login: Date | null;
}

export interface EvidenceRow {
  id: string;
  evidence_number: string;
  case_id: string;
  evidence_type: string;
  file_name: string;
  sha256_hash: string;
  hmac_signature: string;
  collected_at: Date;
  created_at: Date;
  is_tamper_detected: boolean;
  status: string;
  [key: string]: unknown;
}

export interface CustodyRow {
  id: string;
  evidence_id: string;
  sequence_num: number;
  action: string;
  record_hash: string;
  hash_at_time: string;
  occurred_at: Date;
  to_name?: string;
  from_name?: string;
}
