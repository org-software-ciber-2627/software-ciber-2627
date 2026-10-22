# SEM-65 local implementation plan

Scope: connect the existing validated `POST /events` request to PostgreSQL. Keep the current producer schema and static alert endpoints. Work on `equipo-05-siem`; no GitHub writes, Dockerfile edits or real `.env` access.

JC accepted the following proposal, subject to team ratification. Published GitHub contracts/branches and the Miro contract/agreement sections were checked on 2026-10-22; no current Sprint 2 duplicate policy or published SEM-24 validation update was found.

1. Add failing HTTP tests for durable receipts, replay, conflicts, concurrent requests, invalid input and unavailable storage.
2. Insert with PostgreSQL `ON CONFLICT (source, event_id) DO NOTHING`. If already present, compare all content using exact text fields and PostgreSQL JSONB equality. Never overwrite. JSON object key order and equivalent numeric representations do not constitute a change; array order does. Timestamp text is preserved and compared exactly. Legacy SQL rows without original timestamp use the normalized stored instant as fallback.
3. Validate first, then store. Return 200 only after confirmed insert or matching replay; return 409 for conflicting content and 503 for missing/unavailable storage. Without the `persistence` profile, health and alert mocks remain available but event ingestion returns 503.
4. Keep Darío's current validation and its error handler untouched. Add a separate handler for storage errors without exposing SQL, credentials or payloads.
5. Verify against an isolated PostgreSQL volume and the default profile. Record results and leave Jira in review pending JC and team acceptance. Do not apply migrations to JC's existing volume automatically.

Successful receipt: `{"status":"success","message":"Event stored successfully","event_id":"..."}` for both first storage and identical replay. Errors retain `{"error":{"code":"...","message":"..."}}`.
