CREATE TABLE generation_catalog (
    generation_id bytea PRIMARY KEY CHECK (octet_length(generation_id) = 16),
    app_id bytea NOT NULL CHECK (octet_length(app_id) = 16),
    build_id bytea NOT NULL CHECK (octet_length(build_id) = 16),
    function_id bytea NOT NULL CHECK (octet_length(function_id) = 16),
    module_id bytea NOT NULL CHECK (octet_length(module_id) = 16),
    module_version bigint NOT NULL CHECK (module_version > 0),
    descriptor_sha256 bytea NOT NULL CHECK (octet_length(descriptor_sha256) = 32),
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    signing_key_id bytea NOT NULL CHECK (octet_length(signing_key_id) = 32),
    release_expires_ms bigint NOT NULL CHECK (release_expires_ms > 0),
    form smallint NOT NULL CHECK (form IN (1,2)),
    capabilities smallint NOT NULL CHECK (capabilities IN (0,1)),
    ordinal bigint GENERATED ALWAYS AS IDENTITY,
    allocated boolean NOT NULL DEFAULT false,
    UNIQUE (app_id, module_id, module_version),
    FOREIGN KEY (app_id, module_id, module_version) REFERENCES package_releases(app_id,module_id,version)
);

CREATE INDEX generation_catalog_scope ON generation_catalog (app_id,build_id,function_id,generation_id)
    WHERE NOT allocated;

CREATE TABLE generation_offers (
    device_id bytea NOT NULL REFERENCES devices(id),
    request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
    digest bytea NOT NULL CHECK (octet_length(digest) = 32),
    PRIMARY KEY (device_id, request_id)
);

CREATE TABLE generation_selections (
    device_id bytea NOT NULL REFERENCES devices(id),
    request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
    session_id bytea NOT NULL UNIQUE CHECK (octet_length(session_id) = 16),
    generation_id bytea NOT NULL UNIQUE REFERENCES generation_catalog(generation_id),
    challenge_id bytea NOT NULL UNIQUE CHECK (octet_length(challenge_id) = 16),
    choice bytea NOT NULL CHECK (octet_length(choice) = 461),
    service_epoch bigint NOT NULL CHECK (service_epoch > 0),
    expires_tick_ms bigint NOT NULL CHECK (expires_tick_ms >= 0),
    consumed boolean NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, request_id),
    FOREIGN KEY (device_id, request_id) REFERENCES generation_offers(device_id, request_id)
);
