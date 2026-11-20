-- Referencia del esquema de today_db (esquema app_sec) conforme al SRS.
--
-- La base de datos se administra de forma independiente en PostgreSQL (192.168.123.21).
-- Este archivo NO lo ejecuta la aplicación al iniciar: documenta la estructura
-- objetivo con la que opera el backend bajo el rol de mínimo privilegio `today_app`.
--
-- Convenciones de seguridad:
--   * Campos cifrados (*_enc BYTEA): paquete AEAD AES-256-GCM en una sola columna
--     `nonce (12B) || ciphertext || auth_tag (16B)` acompañado de `key_version`.
--   * La llave maestra (APP_ENCRYPTION_KEY) vive exclusivamente en el webserver.
--   * Sin columna CVV/CVC por diseño (prohibición estricta PCI-DSS).
--   * Rol `today_app`: SELECT, INSERT, UPDATE en users/user_pii/user_phi/user_credit_info;
--     SELECT, INSERT (append-only) en auth_attempts y audit_logs.

CREATE SCHEMA IF NOT EXISTS app_sec;

CREATE TABLE app_sec.users (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email                 VARCHAR(255) NOT NULL UNIQUE,
    password_hash         TEXT NOT NULL,
    role                  VARCHAR(20) NOT NULL DEFAULT 'user',
    totp_secret_enc       BYTEA NOT NULL,
    totp_key_version      SMALLINT NOT NULL DEFAULT 1,
    is_2fa_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    last_totp_timestep    BIGINT NOT NULL DEFAULT 0,
    failed_login_attempts SMALLINT NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ NULL,
    is_active             BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at         TIMESTAMPTZ NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_users_email_norm CHECK (email = LOWER(TRIM(email))),
    CONSTRAINT chk_users_role CHECK (role IN ('user', 'admin')),
    CONSTRAINT chk_users_failed_attempts CHECK (failed_login_attempts >= 0)
);

CREATE TABLE app_sec.user_pii (
    user_id     UUID PRIMARY KEY REFERENCES app_sec.users(id) ON DELETE CASCADE,
    full_name   VARCHAR(150) NOT NULL,
    doc_type    VARCHAR(20) NOT NULL,
    doc_number  VARCHAR(50) NOT NULL,
    birth_date  DATE NOT NULL,
    phone       VARCHAR(30) NOT NULL,
    address     VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_pii_doc_type CHECK (doc_type IN ('CC', 'CE', 'PASAPORTE', 'TI', 'NIT')),
    CONSTRAINT chk_pii_birth_date CHECK (birth_date <= CURRENT_DATE),
    CONSTRAINT uq_pii_document UNIQUE (doc_type, doc_number)
);

CREATE TABLE app_sec.user_phi (
    user_id                UUID PRIMARY KEY REFERENCES app_sec.users(id) ON DELETE CASCADE,
    blood_type_enc         BYTEA NOT NULL,
    allergies_enc          BYTEA NULL,
    medical_conditions_enc BYTEA NULL,
    insurance_provider_enc BYTEA NOT NULL,
    key_version            SMALLINT NOT NULL DEFAULT 1,
    consent_accepted       BOOLEAN NOT NULL,
    consent_accepted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_phi_consent CHECK (consent_accepted = TRUE)
);

CREATE TABLE app_sec.user_credit_info (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES app_sec.users(id) ON DELETE CASCADE,
    cardholder_name_enc BYTEA NOT NULL,
    pan_enc             BYTEA NOT NULL,
    exp_date_enc        BYTEA NOT NULL,
    card_last4          CHAR(4) NOT NULL,
    card_brand          VARCHAR(30) NOT NULL,
    key_version         SMALLINT NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_credit_last4 CHECK (card_last4 ~ '^[0-9]{4}$')
);

CREATE TABLE app_sec.auth_attempts (
    id              BIGSERIAL PRIMARY KEY,
    email_attempted VARCHAR(255) NOT NULL,
    user_id         UUID NULL REFERENCES app_sec.users(id) ON DELETE SET NULL,
    source_ip       INET NOT NULL,
    result_code     VARCHAR(40) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE app_sec.audit_logs (
    id             BIGSERIAL PRIMARY KEY,
    actor_user_id  UUID NULL REFERENCES app_sec.users(id) ON DELETE SET NULL,
    target_user_id UUID NULL REFERENCES app_sec.users(id) ON DELETE SET NULL,
    event_type     VARCHAR(50) NOT NULL,
    source_ip      INET NOT NULL,
    metadata       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_locked_until ON app_sec.users (locked_until) WHERE locked_until IS NOT NULL;
CREATE INDEX idx_credit_user_id ON app_sec.user_credit_info (user_id);
CREATE INDEX idx_auth_attempts_email_time ON app_sec.auth_attempts (email_attempted, created_at DESC);
CREATE INDEX idx_auth_attempts_ip_time ON app_sec.auth_attempts (source_ip, created_at DESC);
CREATE INDEX idx_audit_event_time ON app_sec.audit_logs (event_type, created_at DESC);
CREATE INDEX idx_audit_actor_time ON app_sec.audit_logs (actor_user_id, created_at DESC);
