-- Rows describe device claims. Device authentication does not attest the contents.
CREATE TABLE session_observation_reports (
    device_id bytea NOT NULL REFERENCES devices(id),
    request_id bytea NOT NULL CHECK (octet_length(request_id) = 16),
    session_id bytea NOT NULL REFERENCES sessions(id),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    detection_policy_epoch bigint NOT NULL CHECK (detection_policy_epoch > 0),
    action smallint NOT NULL CHECK (action IN (1, 2)),
    records bytea NOT NULL CHECK (octet_length(records) BETWEEN 4 AND 32
        AND octet_length(records) % 4 = 0),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (device_id, request_id)
);

CREATE INDEX session_observation_report_quota ON session_observation_reports (session_id)
    WHERE action = 1;
CREATE UNIQUE INDEX session_observation_one_stop ON session_observation_reports (session_id)
    WHERE action = 2;
