CREATE TABLE protected_operations (
    app_id bytea NOT NULL CHECK (octet_length(app_id)=16),
    build_id bytea NOT NULL CHECK (octet_length(build_id)=16),
    function_id bytea NOT NULL CHECK (octet_length(function_id)=16),
    operation_id bytea NOT NULL CHECK (octet_length(operation_id)=16),
    signing_key_id bytea NOT NULL CHECK (octet_length(signing_key_id)=32),
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (app_id,build_id,function_id,operation_id)
);

CREATE TABLE protected_operation_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app_id bytea NOT NULL,
    build_id bytea NOT NULL,
    function_id bytea NOT NULL,
    operation_id bytea NOT NULL,
    actor_id bytea NOT NULL CHECK (octet_length(actor_id)=16),
    action text NOT NULL CHECK (action IN ('configured','disabled')),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (app_id,build_id,function_id,operation_id)
        REFERENCES protected_operations(app_id,build_id,function_id,operation_id)
);

CREATE TABLE operation_requests (
    device_id bytea NOT NULL REFERENCES devices(id),
    request_id bytea NOT NULL CHECK (octet_length(request_id)=16),
    session_id bytea NOT NULL REFERENCES sessions(id),
    operation_id bytea NOT NULL CHECK (octet_length(operation_id)=16),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    receipt bytea NOT NULL CHECK (octet_length(receipt)=391),
    PRIMARY KEY (device_id,request_id)
);
