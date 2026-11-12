CREATE TABLE session_service (
    singleton boolean PRIMARY KEY CHECK (singleton),
    epoch bigint NOT NULL CHECK (epoch > 0),
    policy_epoch bigint NOT NULL CHECK (policy_epoch > 0)
);

CREATE TABLE sessions (
    id bytea PRIMARY KEY CHECK (octet_length(id) = 16),
    license_id bytea NOT NULL,
    device_id bytea NOT NULL,
    build_id bytea NOT NULL CHECK (octet_length(build_id) = 16),
    generation_id bytea NOT NULL CHECK (octet_length(generation_id) = 16),
    service_epoch bigint NOT NULL CHECK (service_epoch > 0),
    sequence bigint NOT NULL CHECK (sequence > 0),
    expires_tick_ms bigint NOT NULL CHECK (expires_tick_ms >= 0),
    stopped boolean NOT NULL DEFAULT false,
    FOREIGN KEY (license_id, device_id) REFERENCES devices(license_id, id)
);

CREATE UNIQUE INDEX sessions_one_current_license ON sessions (license_id)
    WHERE NOT stopped;

CREATE TABLE session_requests (
    device_id bytea NOT NULL REFERENCES devices(id),
    request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
    challenge_id bytea NOT NULL UNIQUE CHECK (octet_length(challenge_id) = 16),
    intent bytea NOT NULL CHECK (octet_length(intent) = 145),
    challenge bytea NOT NULL CHECK (octet_length(challenge) = 120),
    service_epoch bigint NOT NULL CHECK (service_epoch > 0),
    expires_tick_ms bigint NOT NULL CHECK (expires_tick_ms >= 0),
    consumed boolean NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, request_id)
);

CREATE TABLE session_rates (
    device_id bytea PRIMARY KEY REFERENCES devices(id),
    service_epoch bigint NOT NULL CHECK (service_epoch > 0),
    last_tick_ms bigint NOT NULL CHECK (last_tick_ms >= 0),
    credit bigint NOT NULL CHECK (credit BETWEEN 0 AND 120000)
);
