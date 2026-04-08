/**
 * GTSAlpha Forensics — Super Admin Creation Script
 * Creates the initial super_admin operator (SA-001) or any subsequent admins.
 * 
 * Usage:
 *   npm run create:admin <badge_number> <full_name> <password>
 * 
 * Example:
 *   npm run create:admin SA-001 "Commander Phuphadang" "strongpassword123!"
 */

import { config } from 'dotenv';
import bcrypt     from 'bcryptjs';

// Load .env before importing pool
config();

// Dynamic import for ESM compatibility and ensuring env vars are loaded
const { pool } = await import('../src/config/database.js');

async function main() {
  const badgeNumber = process.argv[2];
  const fullName    = process.argv[3];
  const password    = process.argv[4];

  // 1. Basic Validation
  if (!badgeNumber || !fullName || !password) {
    console.error('❌ Missing arguments.');
    console.log('Usage: npm run create:admin <badge_number> <full_name> <password>');
    process.exit(1);
  }

  if (!/^SA-\d{3}$/.test(badgeNumber)) {
    console.error('❌ Invalid badge_number format. Must match SA-### (e.g., SA-001)');
    process.exit(1);
  }

  if (password.length < 12) {
    console.error('❌ Password must be at least 12 characters long.');
    process.exit(1);
  }

  console.log(`🚀 Creating Super Admin: ${badgeNumber} (${fullName}) ...`);

  try {
    // 2. Hash password (12 rounds as requested)
    const saltRounds   = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // 3. Insert into operators table
    // Using ON CONFLICT (badge_number) DO NOTHING to prevent duplicates
    const { rows } = await pool.query(
      `INSERT INTO operators (badge_number, full_name, role, password_hash, is_active)
       VALUES ($1, $2, 'super_admin', $3, true)
       ON CONFLICT (badge_number) DO NOTHING
       RETURNING id, badge_number`,
      [badgeNumber, fullName, passwordHash]
    );

    if (rows.length === 0) {
      console.warn(`⚠️ Operator with badge_number "${badgeNumber}" already exists.`);
    } else {
      const admin = rows[0];
      console.log('✅ Super Admin created successfully.');
      console.log(`   ID          : ${admin.id}`);
      console.log(`   Badge Number: ${admin.badge_number}`);
    }

  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`❌ Error creating admin: ${msg}`);
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('❌ Unexpected error:', err);
  process.exit(1);
});
