-- Preserve existing rows while extending the common event severity catalog.
BEGIN;
SET LOCAL lock_timeout = '5s';
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_severity_check;
ALTER TABLE events ADD CONSTRAINT events_severity_check
    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical'));
COMMIT;
