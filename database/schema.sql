-- =============================================================================
-- GTSAlpha Forensics — Database Schema v1.0.0
-- Digital Evidence Management System
-- Standard: ISO/IEC 27037 (Digital Evidence Identification & Preservation)
-- Date: 2026-04-08
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "earthdistance" CASCADE; -- for geo queries

-- ---------------------------------------------------------------------------
-- OPERATORS  (RBAC — Role-Based Access Control)
-- ---------------------------------------------------------------------------
CREATE TABLE operators (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  badge_number   VARCHAR(50)  UNIQUE NOT NULL,
  full_name      VARCHAR(200) NOT NULL,
  role           VARCHAR(30)  NOT NULL
                   CHECK (role IN ('super_admin','c3_commander','analyst','viewer')),
  department     VARCHAR(100),
  password_hash  VARCHAR(255) NOT NULL,
  public_key     TEXT,                        -- RSA-2048 public key (PEM) for e-sig
  is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
  last_login     TIMESTAMPTZ,
  failed_login   INTEGER      NOT NULL DEFAULT 0,
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_operators_badge ON operators(badge_number);
CREATE INDEX idx_operators_role  ON operators(role);

-- ---------------------------------------------------------------------------
-- CASES
-- ---------------------------------------------------------------------------
CREATE TABLE cases (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  case_number    VARCHAR(50)  UNIQUE NOT NULL,
  title          TEXT         NOT NULL,
  status         VARCHAR(20)  NOT NULL DEFAULT 'open'
                   CHECK (status IN ('open','active','closed','archived')),
  classification VARCHAR(20)  NOT NULL DEFAULT 'confidential'
                   CHECK (classification IN ('public','restricted','confidential','secret')),
  description    TEXT,
  created_by     UUID         NOT NULL REFERENCES operators(id),
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  closed_at      TIMESTAMPTZ,
  metadata       JSONB        NOT NULL DEFAULT '{}',
  integrity_hash VARCHAR(64)  NOT NULL DEFAULT ''
    -- SHA-256(case_number || title || created_by || created_at)
);

CREATE INDEX idx_cases_number ON cases(case_number);
CREATE INDEX idx_cases_status ON cases(status);

-- ---------------------------------------------------------------------------
-- EVIDENCE
-- ---------------------------------------------------------------------------
CREATE TABLE evidence (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  evidence_number    VARCHAR(100) UNIQUE NOT NULL,
  case_id            UUID         NOT NULL REFERENCES cases(id),
  evidence_type      VARCHAR(50)  NOT NULL
                       CHECK (evidence_type IN (
                         'image','video','audio','document','biometric',
                         'network_log','device_image','location_data',
                         'social_media','other'
                       )),
  file_name          VARCHAR(500) NOT NULL,
  file_size          BIGINT,
  mime_type          VARCHAR(100),
  storage_path       TEXT         NOT NULL,
  sha256_hash        VARCHAR(64)  NOT NULL,       -- SHA-256 hash of file content
  hmac_signature     VARCHAR(128) NOT NULL,       -- HMAC-SHA256 server integrity seal
  source_device      VARCHAR(200),
  source_ip          INET,
  acquisition_method VARCHAR(100),               -- e.g. CCTV_capture, manual_upload
  collected_by       UUID         NOT NULL REFERENCES operators(id),
  collected_at       TIMESTAMPTZ  NOT NULL,
  received_by        UUID         REFERENCES operators(id),
  received_at        TIMESTAMPTZ,
  status             VARCHAR(30)  NOT NULL DEFAULT 'received'
                       CHECK (status IN (
                         'received','queued','analyzing','analyzed',
                         'submitted_to_court','rejected'
                       )),
  is_tamper_detected BOOLEAN      NOT NULL DEFAULT FALSE,
  metadata           JSONB        NOT NULL DEFAULT '{}',
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_evidence_case    ON evidence(case_id);
CREATE INDEX idx_evidence_hash    ON evidence(sha256_hash);
CREATE INDEX idx_evidence_type    ON evidence(evidence_type);
CREATE INDEX idx_evidence_status  ON evidence(status);
CREATE INDEX idx_evidence_number  ON evidence(evidence_number);

-- ---------------------------------------------------------------------------
-- CHAIN OF CUSTODY  (Append-only — no UPDATE/DELETE permitted)
-- ---------------------------------------------------------------------------
CREATE TABLE custody_chain (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  evidence_id   UUID         NOT NULL REFERENCES evidence(id),
  sequence_num  INTEGER      NOT NULL,
  action        VARCHAR(50)  NOT NULL
                  CHECK (action IN (
                    'received','transferred','analyzed','copied',
                    'submitted','sealed','unsealed','returned'
                  )),
  from_operator UUID         REFERENCES operators(id),
  to_operator   UUID         REFERENCES operators(id),
  location      TEXT,
  reason        TEXT,
  notes         TEXT,
  hash_at_time  VARCHAR(64)  NOT NULL,   -- sha256_hash of evidence at this moment
  record_hash   VARCHAR(64)  NOT NULL,   -- SHA-256(prev_hash||evidence_id||action||to_op||ts)
  occurred_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

  UNIQUE (evidence_id, sequence_num)
);

CREATE INDEX idx_custody_evidence ON custody_chain(evidence_id, sequence_num);

-- Prevent modification of the Chain of Custody (immutability guarantee)
CREATE RULE no_update_custody AS ON UPDATE TO custody_chain DO INSTEAD NOTHING;
CREATE RULE no_delete_custody AS ON DELETE TO custody_chain DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- CHRONOS EVENTS  (AI Unit output — The Watcher / Interpreter / Prophet / Hunter)
-- ---------------------------------------------------------------------------
CREATE TABLE chronos_events (
  id               UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id          UUID             REFERENCES cases(id),
  evidence_id      UUID             REFERENCES evidence(id),
  event_type       VARCHAR(60)      NOT NULL
                     CHECK (event_type IN (
                       'face_detection','face_match','vehicle_detection',
                       'ocr_read','lpr_read','location_track',
                       'nlp_intent','nlp_sentiment',
                       'path_prediction','osint_hit','object_detection'
                     )),
  unit             VARCHAR(20)      NOT NULL
                     CHECK (unit IN ('WATCHER','INTERPRETER','PROPHET','HUNTER')),
  model_used       VARCHAR(100),
  confidence_score FLOAT            CHECK (confidence_score BETWEEN 0 AND 1),
  raw_data         JSONB            NOT NULL,
  processed_data   JSONB            NOT NULL DEFAULT '{}',
  location_lat     DOUBLE PRECISION CHECK (location_lat  BETWEEN -90  AND  90),
  location_lon     DOUBLE PRECISION CHECK (location_lon  BETWEEN -180 AND 180),
  frame_timestamp  TIMESTAMPTZ,
  source_device    VARCHAR(200),
  operator_id      UUID             NOT NULL REFERENCES operators(id),
  sha256_hash      VARCHAR(64)      NOT NULL,  -- SHA-256(raw_data JSON + created_at)
  created_at       TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chronos_case       ON chronos_events(case_id);
CREATE INDEX idx_chronos_event_type ON chronos_events(event_type);
CREATE INDEX idx_chronos_unit       ON chronos_events(unit);
CREATE INDEX idx_chronos_created    ON chronos_events(created_at DESC);

-- ---------------------------------------------------------------------------
-- MCP SESSIONS  (AI Agent access tokens — granular tool permissions)
-- ---------------------------------------------------------------------------
CREATE TABLE mcp_sessions (
  id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  session_token VARCHAR(512) UNIQUE NOT NULL,
  operator_id   UUID         NOT NULL REFERENCES operators(id),
  allowed_tools TEXT[]       NOT NULL DEFAULT '{}',
  case_scope    UUID[]       NOT NULL DEFAULT '{}',  -- empty = all authorized cases
  expires_at    TIMESTAMPTZ  NOT NULL,
  revoked_at    TIMESTAMPTZ,
  created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mcp_token    ON mcp_sessions(session_token);
CREATE INDEX idx_mcp_operator ON mcp_sessions(operator_id);

-- ---------------------------------------------------------------------------
-- INTEL REPORTS  (AI-generated analysis output)
-- ---------------------------------------------------------------------------
CREATE TABLE intel_reports (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id          UUID        NOT NULL REFERENCES cases(id),
  report_type      VARCHAR(50) NOT NULL
                     CHECK (report_type IN (
                       'entity_link_analysis','timeline','path_prediction',
                       'osint_summary','threat_assessment','court_ready_summary'
                     )),
  title            TEXT        NOT NULL,
  content          TEXT        NOT NULL,
  sources          JSONB       NOT NULL DEFAULT '[]',   -- array of evidence/event IDs
  confidence_level VARCHAR(10) CHECK (confidence_level IN ('high','medium','low')),
  model_used       VARCHAR(100),
  is_court_ready   BOOLEAN     NOT NULL DEFAULT FALSE,
  reviewed_by      UUID        REFERENCES operators(id),
  reviewed_at      TIMESTAMPTZ,
  created_by       UUID        NOT NULL REFERENCES operators(id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_case ON intel_reports(case_id);

-- ---------------------------------------------------------------------------
-- AUDIT LOG  (Immutable linked-hash chain — append-only)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  id              BIGSERIAL    PRIMARY KEY,
  operator_id     UUID         REFERENCES operators(id),
  session_id      UUID,
  action_type     VARCHAR(100) NOT NULL,
  resource_type   VARCHAR(50),
  resource_id     UUID,
  case_number     VARCHAR(50),
  ip_address      INET,
  user_agent      TEXT,
  request_summary JSONB        NOT NULL DEFAULT '{}',
  response_status SMALLINT,
  prev_hash       VARCHAR(64)  NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
  integrity_hash  VARCHAR(64)  NOT NULL,
    -- SHA-256(prev_hash || operator_id || action_type || occurred_at)
  occurred_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_operator ON audit_log(operator_id);
CREATE INDEX idx_audit_action   ON audit_log(action_type);
CREATE INDEX idx_audit_occurred ON audit_log(occurred_at DESC);

-- Immutability guarantee
CREATE RULE no_update_audit AS ON UPDATE TO audit_log DO INSTEAD NOTHING;
CREATE RULE no_delete_audit  AS ON DELETE TO audit_log DO INSTEAD NOTHING;

-- ---------------------------------------------------------------------------
-- DEFAULT SUPER ADMIN
-- Badge: SA-001  |  Temporary password: GTSAlpha@2026!
-- IMPORTANT: Change password immediately after first login
-- Hash generated with bcrypt rounds=12
-- ---------------------------------------------------------------------------
INSERT INTO operators (badge_number, full_name, role, department, password_hash)
VALUES (
  'SA-001',
  'System Administrator',
  'super_admin',
  'GTSAlpha Forensics Operations',
  '$2b$12$PLACEHOLDER_RUN_scripts/create_admin.ts_TO_GENERATE_REAL_HASH'
);

COMMIT;
