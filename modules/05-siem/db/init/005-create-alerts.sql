-- Persist generated alerts so they survive restarts (SEM-121 / HU23). Safe to apply more than once.
BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    alert JSONB NOT NULL CHECK (jsonb_typeof(alert) = 'object'),
    -- IS NOT DISTINCT FROM rejects a missing or JSON null key; a plain = would yield NULL and pass the CHECK.
    CONSTRAINT alerts_identity_matches CHECK (
        (alert -> 'alert_id') IS NOT DISTINCT FROM to_jsonb(alert_id)
        AND (alert -> 'source') IS NOT DISTINCT FROM to_jsonb(source)
        AND (alert -> 'event_id') IS NOT DISTINCT FROM to_jsonb(event_id)
    ),
    CONSTRAINT alerts_event_unique UNIQUE (source, event_id),
    CONSTRAINT alerts_event_fk FOREIGN KEY (source, event_id) REFERENCES events (source, event_id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_created_at
    ON alerts (created_at, alert_id);
COMMIT;
