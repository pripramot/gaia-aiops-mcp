import crypto from 'node:crypto';

const HMAC_SECRET = process.env['HMAC_SECRET'] ?? 'CHANGE_ME_IMMEDIATELY';

/**
 * SHA-256 hash of arbitrary string or Buffer. Returns lower-case hex.
 */
export function sha256(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * HMAC-SHA256 signature.  Used to sign evidence records at ingest time.
 */
export function hmacSign(data: string): string {
  return crypto.createHmac('sha256', HMAC_SECRET).update(data).digest('hex');
}

/**
 * Timing-safe HMAC-SHA256 verification.
 * Returns true only when the recomputed and supplied signatures are identical.
 */
export function hmacVerify(data: string, signature: string): boolean {
  const expected = hmacSign(data);
  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected,  'hex'),
      Buffer.from(signature, 'hex'),
    );
  } catch {
    // Buffers of different length — clear mismatch
    return false;
  }
}

/**
 * Canonical string for evidence signing:
 *   sha256Hash | evidenceNumber | caseId | collectedAt
 *
 * ISO/IEC 27037 — the canonical form must be deterministic and reproducible
 * so the hash can be independently validated by any auditor with the secret.
 */
export function buildEvidenceCanonical(params: {
  sha256Hash:      string;
  evidenceNumber:  string;
  caseId:          string;
  collectedAt:     string;
}): string {
  return [
    params.sha256Hash,
    params.evidenceNumber,
    params.caseId,
    params.collectedAt,
  ].join('|');
}

/**
 * Audit-log chain integrity hash:
 *   SHA-256( prevHash | operatorId | actionType | occurredAt )
 */
export function chainHash(
  prevHash:   string,
  operatorId: string,
  action:     string,
  ts:         string,
): string {
  return sha256(`${prevHash}|${operatorId}|${action}|${ts}`);
}

/**
 * Chain-of-custody record hash:
 *   SHA-256( prevHash | evidenceId | action | toOperator | occurredAt )
 */
export function custodyRecordHash(
  prevHash:   string,
  evidenceId: string,
  action:     string,
  toOperator: string,
  occurredAt: string,
): string {
  return sha256(`${prevHash}|${evidenceId}|${action}|${toOperator}|${occurredAt}`);
}
