CREATE TABLE IF NOT EXISTS events (
    event_id TEXT NOT NULL CHECK (event_id ~ '[^[:space:]]'),
    occurred_at TIMESTAMPTZ NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('ids', 'honeypot', 'scanner')),
    event_type TEXT NOT NULL CHECK (event_type ~ '[^[:space:]]'),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    title TEXT NOT NULL CHECK (title ~ '[^[:space:]]'),
    description TEXT NOT NULL CHECK (description ~ '[^[:space:]]'),
    details JSONB NOT NULL CHECK (jsonb_typeof(details) = 'object'),
    PRIMARY KEY (source, event_id)
);

CREATE INDEX IF NOT EXISTS idx_events_occurred_at
    ON events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_source
    ON events (source);
