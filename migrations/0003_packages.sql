CREATE TABLE package_trust (
    app_id bytea PRIMARY KEY CHECK (octet_length(app_id) = 16),
    epoch bigint NOT NULL CHECK (epoch > 0),
    wall_floor_ms bigint NOT NULL CHECK (wall_floor_ms >= 0),
    bundle bytea NOT NULL CHECK (octet_length(bundle) BETWEEN 1 AND 4194304)
);

CREATE TABLE package_revoked_keys (
    app_id bytea NOT NULL REFERENCES package_trust(app_id),
    key_id bytea NOT NULL CHECK (octet_length(key_id) = 32),
    PRIMARY KEY (app_id, key_id)
);

CREATE TABLE package_releases (
    app_id bytea NOT NULL REFERENCES package_trust(app_id),
    module_id bytea NOT NULL CHECK (octet_length(module_id) = 16),
    version bigint NOT NULL CHECK (version > 0),
    frame bytea NOT NULL CHECK (octet_length(frame) BETWEEN 1 AND 4194304),
    revoked boolean NOT NULL DEFAULT false,
    PRIMARY KEY (app_id, module_id, version)
);

CREATE TABLE package_fetch_requests (
    device_id bytea NOT NULL REFERENCES devices(id),
    request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    delivered boolean NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, request_id)
);

CREATE TABLE package_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app_id bytea NOT NULL REFERENCES package_trust(app_id),
    actor_id bytea NOT NULL CHECK (octet_length(actor_id) = 16),
    action text NOT NULL CHECK (action IN ('trust_installed', 'release_published', 'release_revoked')),
    epoch bigint NOT NULL CHECK (epoch > 0),
    module_id bytea,
    version bigint,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((action = 'trust_installed' AND module_id IS NULL AND version IS NULL)
        OR (action <> 'trust_installed' AND module_id IS NOT NULL AND version IS NOT NULL)),
    FOREIGN KEY (app_id, module_id, version) REFERENCES package_releases(app_id, module_id, version)
);
