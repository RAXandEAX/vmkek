CREATE TABLE recovery_identity (
    singleton boolean PRIMARY KEY CHECK (singleton),
    deployment_id bytea NOT NULL CHECK (octet_length(deployment_id)=16),
    app_id bytea NOT NULL CHECK (octet_length(app_id)=16),
    build_id bytea NOT NULL CHECK (octet_length(build_id)=16),
    history_id bytea NOT NULL CHECK (octet_length(history_id)=16)
);
