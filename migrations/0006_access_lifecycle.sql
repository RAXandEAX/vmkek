ALTER TABLE access_decisions
    DROP CONSTRAINT access_decisions_action_check,
    DROP CONSTRAINT access_decisions_reason_check,
    ADD COLUMN policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    ADD COLUMN request_id bytea,
    ADD COLUMN request_digest bytea,
    ADD COLUMN restore_of bigint UNIQUE REFERENCES access_decisions(id),
    ADD CONSTRAINT access_decisions_actor_request UNIQUE (actor_id, request_id),
    ADD CONSTRAINT access_decisions_request_shape CHECK (
        (request_id IS NULL AND request_digest IS NULL) OR
        (request_id IS NOT NULL AND request_digest IS NOT NULL
            AND octet_length(request_id) = 16 AND octet_length(request_digest) = 32)
    ),
    ADD CONSTRAINT access_decisions_transition CHECK (
        (action = 'revoke' AND reason IN (1, 2) AND restore_of IS NULL) OR
        (action = 'restore' AND reason = 3 AND restore_of IS NOT NULL AND request_id IS NOT NULL)
    );

CREATE INDEX access_decisions_target_history ON access_decisions (license_id, device_id, id DESC);

ALTER TABLE audit
    DROP CONSTRAINT audit_event_check,
    ADD CONSTRAINT audit_event_check CHECK (event IN ('challenge', 'enrolled', 'reused', 'proof_denied',
        'state_denied', 'expired', 'replay', 'device_limit', 'rate_limit', 'trust_denied', 'revoked', 'restored'));

-- A legacy revoked target may still have an unstopped session row.
UPDATE sessions s SET stopped = true
WHERE NOT s.stopped AND (
    EXISTS (SELECT 1 FROM licenses l WHERE l.id = s.license_id AND l.state = 'revoked')
    OR EXISTS (SELECT 1 FROM devices d WHERE d.id = s.device_id AND d.state = 'revoked')
);

UPDATE session_requests r SET consumed = true
FROM devices d JOIN licenses l ON l.id = d.license_id
WHERE r.device_id = d.id AND NOT r.consumed
  AND (l.state = 'revoked' OR d.state = 'revoked');

UPDATE generation_selections s SET consumed = true
FROM devices d JOIN licenses l ON l.id = d.license_id
WHERE s.device_id = d.id AND NOT s.consumed
  AND (l.state = 'revoked' OR d.state = 'revoked');
