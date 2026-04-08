/**
 * GTSAlpha Forensics — Database Migration Script
 * Executes database/schema.sql against the configured PostgreSQL / Supabase instance.
 *
 * Usage (local dev):
 *   cp .env.example .env  # fill in DATABASE_URL
 *   npm run db:migrate
 */

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { config } from 'dotenv';

// Load .env before importing pool (pool reads process.env at module init)
config();

// Dynamic import AFTER dotenv.config() to ensure env vars are available
const { pool } = await import('../src/config/database.js');

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

const schemaPath = join(__dirname, '..', 'database', 'schema.sql');

let sql: string;
try {
  sql = readFileSync(schemaPath, 'utf8');
} catch {
  console.error(`❌ Cannot read schema file: ${schemaPath}`);
  process.exit(1);
}

console.log('🚀 Running migration — database/schema.sql …');

const client = await pool.connect();
try {
  await client.query(sql);
  console.log('✅ Migration complete.');
} catch (err: unknown) {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(`❌ Migration failed: ${msg}`);
  process.exit(1);
} finally {
  client.release();
  await pool.end();
}
