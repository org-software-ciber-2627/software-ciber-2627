CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY CHECK (btrim(event_id) <> ''),
    occurred_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('ids', 'honeypot', 'scanner')),
    event_type TEXT NOT NULL CHECK (btrim(event_type) <> ''),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    title TEXT NOT NULL CHECK (btrim(title) <> ''),
    description TEXT NOT NULL CHECK (btrim(description) <> ''),
    details JSONB NOT NULL CHECK (jsonb_typeof(details) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_events_occurred_at
    ON events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_source
    ON events (source);
