CREATE TABLE licenses (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    app_id bytea NOT NULL CHECK (octet_length(app_id) = 16),
    activation_digest bytea NOT NULL UNIQUE CHECK (octet_length(activation_digest) = 32),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'quarantine', 'revoked')),
    device_limit integer NOT NULL DEFAULT 1 CHECK (device_limit > 0)
);

CREATE TABLE devices (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    license_id bytea NOT NULL REFERENCES licenses(id),
    key_id bytea NOT NULL CHECK (octet_length(key_id) = 32),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 65),
    trust smallint NOT NULL CHECK (trust IN (1, 2)),
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'quarantine', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (license_id, key_id),
    UNIQUE (license_id, id)
);

CREATE TABLE enrollments (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    license_id bytea NOT NULL REFERENCES licenses(id),
    key_id bytea NOT NULL CHECK (octet_length(key_id) = 32),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 65),
    nonce bytea NOT NULL UNIQUE CHECK (octet_length(nonce) = 32),
    trust smallint NOT NULL CHECK (trust IN (1, 2)),
    issued_at timestamptz NOT NULL,
    expires_unix_ms bigint NOT NULL CHECK (expires_unix_ms > 0),
    consumed_at timestamptz,
    UNIQUE (license_id, id)
);

CREATE INDEX enrollments_license_issued ON enrollments (license_id, issued_at);

CREATE TABLE access_decisions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    license_id bytea NOT NULL REFERENCES licenses(id),
    device_id bytea,
    actor_id bytea NOT NULL CHECK (octet_length(actor_id) = 16),
    reason smallint NOT NULL CHECK (reason IN (1, 2)),
    action text NOT NULL CHECK (action = 'revoke'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (license_id, device_id) REFERENCES devices(license_id, id)
);

CREATE TABLE audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    license_id bytea NOT NULL REFERENCES licenses(id),
    challenge_id bytea,
    device_id bytea,
    decision_id bigint REFERENCES access_decisions(id),
    event text NOT NULL CHECK (event IN ('challenge', 'enrolled', 'reused', 'proof_denied',
        'state_denied', 'expired', 'replay', 'device_limit', 'rate_limit', 'trust_denied', 'revoked')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (license_id, challenge_id) REFERENCES enrollments(license_id, id),
    FOREIGN KEY (license_id, device_id) REFERENCES devices(license_id, id)
);
