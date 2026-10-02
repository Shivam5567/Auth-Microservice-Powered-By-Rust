-- Registry of the downstream services that consume this auth service.
--
-- A service is governance metadata plus a revocation handle: `token_version`
-- is stamped into any access token minted for that service, so disabling it or
-- bumping the version makes tokens already in flight stop verifying.

CREATE TABLE services (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Lowercase slug. Stable and safe to embed in URLs and token claims.
    name          TEXT        NOT NULL UNIQUE,
    description   TEXT        NOT NULL DEFAULT '',
    status        TEXT        NOT NULL DEFAULT 'active'
                              CHECK (status IN ('active', 'disabled')),
    scopes        TEXT[]      NOT NULL DEFAULT '{}',
    token_version INTEGER     NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Set when the service is removed. The row is kept so history survives.
    disabled_at   TIMESTAMPTZ
);

CREATE INDEX idx_services_status ON services (status);

-- Which service a session was opened for. Refreshed tokens inherit it, so a
-- decommissioned service's sessions cannot be quietly upgraded into unbound
-- ones by exchanging a refresh token.
ALTER TABLE refresh_tokens ADD COLUMN service_name TEXT;

CREATE INDEX idx_refresh_tokens_service_name ON refresh_tokens (service_name);

-- Append-only trail of administrative changes, so a decommission can be
-- explained after the fact.
CREATE TABLE service_events (
    id           BIGSERIAL   PRIMARY KEY,
    service_id   UUID        REFERENCES services (id) ON DELETE CASCADE,
    -- Denormalised because a hard delete would otherwise erase the trail.
    service_name TEXT        NOT NULL,
    action       TEXT        NOT NULL,
    actor        TEXT,
    detail       TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_service_events_service ON service_events (service_id, created_at DESC);
CREATE INDEX idx_service_events_created ON service_events (created_at DESC);
