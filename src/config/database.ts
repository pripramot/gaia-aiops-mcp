import pg, { type QueryResultRow } from 'pg';
import { logger } from '../utils/logger.js';

const { Pool } = pg;

// Supabase / cloud DB: ใช้ DATABASE_URL เดียว ถ้ามี
// Local / self-hosted:  ใช้ DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
const connectionConfig = process.env['DATABASE_URL']
  ? {
      connectionString: process.env['DATABASE_URL'],
      max: 20,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      ssl: { rejectUnauthorized: false }, // Supabase ต้องการ SSL เสมอ
    }
  : {
      host:     process.env['DB_HOST']     ?? 'localhost',
      port:     Number(process.env['DB_PORT'] ?? 5432),
      database: process.env['DB_NAME']     ?? 'gtsalpha_forensics',
      user:     process.env['DB_USER']     ?? 'gtsalpha',
      password: process.env['DB_PASSWORD'],
      max:      20,
      idleTimeoutMillis:       30_000,
      connectionTimeoutMillis: 5_000,
      ssl: process.env['DB_SSL'] === 'true' ? { rejectUnauthorized: false } : undefined,
    };

export const pool = new Pool(connectionConfig);

pool.on('error', (err: Error) => {
  logger.error('Unexpected DB pool error', { message: err.message });
});

export async function query<T extends QueryResultRow = QueryResultRow>(
  text: string,
  params?: unknown[],
): Promise<{ rows: T[]; rowCount: number | null }> {
  const res = await pool.query<T>(text, params);
  return { rows: res.rows, rowCount: res.rowCount };
}
