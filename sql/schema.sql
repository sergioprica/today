-- Referencia del esquema de today_db.
--
-- La base de datos ya existe en su propia máquina virtual (192.168.123.21) y se
-- administra allí. Este archivo NO lo ejecuta la app: solo documenta las tablas
-- con las que trabaja el código. Si el esquema cambia en el servidor, actualiza
-- también este archivo.
--
-- Los campos sensibles se guardan como <campo>_ciphertext + <campo>_nonce
-- (AES-256-GCM). La clave AES vive solo en el webserver (APP_ENCRYPTION_KEY).

CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,

    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(200) NOT NULL,

    password_hash TEXT NOT NULL,

    totp_secret_ciphertext BYTEA,
    totp_secret_nonce BYTEA,

    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_pii (
    user_id BIGINT PRIMARY KEY
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    phone_ciphertext BYTEA,
    phone_nonce BYTEA,

    document_type VARCHAR(30),

    document_number_ciphertext BYTEA,
    document_number_nonce BYTEA,

    birth_date_ciphertext BYTEA,
    birth_date_nonce BYTEA,

    address_ciphertext BYTEA,
    address_nonce BYTEA,

    city VARCHAR(100),
    country VARCHAR(100),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE credit_profiles (
    credit_profile_id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    credit_score INTEGER,

    monthly_income_ciphertext BYTEA,
    monthly_income_nonce BYTEA,

    total_debt_ciphertext BYTEA,
    total_debt_nonce BYTEA,

    credit_limit_ciphertext BYTEA,
    credit_limit_nonce BYTEA,

    credit_status VARCHAR(20)
        CHECK (
            credit_status IN (
                'GOOD',
                'STANDARD',
                'POOR',
                'UNKNOWN'
            )
        ),

    risk_level VARCHAR(30),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE health_information (
    health_record_id BIGSERIAL PRIMARY KEY,

    user_id BIGINT NOT NULL
        REFERENCES users(user_id)
        ON DELETE CASCADE,

    medical_record_number_ciphertext BYTEA,
    medical_record_number_nonce BYTEA,

    health_condition_ciphertext BYTEA,
    health_condition_nonce BYTEA,

    medication_ciphertext BYTEA,
    medication_nonce BYTEA,

    insurance_number_ciphertext BYTEA,
    insurance_number_nonce BYTEA,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
