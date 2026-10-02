-- Orders, and the only link back to the auth service is `user_id`.

CREATE TABLE orders (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The auth service's user id. Deliberately not a foreign key across
    -- services: the two databases have no shared transaction, and coupling them
    -- would make an auth-side outage into an orders-side outage.
    user_id      UUID        NOT NULL,
    status       TEXT        NOT NULL DEFAULT 'pending'
                             CHECK (status IN ('pending', 'paid', 'refunded', 'cancelled')),
    -- BIGINT, not INTEGER: cents are a 32-bit int in Postgres but the Rust type
    -- is i64, and a per-unit price times a quantity should not be able to wrap.
    total_cents  BIGINT      NOT NULL CHECK (total_cents >= 0),
    currency     TEXT        NOT NULL DEFAULT 'USD',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_orders_user_id ON orders (user_id, created_at DESC);
CREATE INDEX idx_orders_status ON orders (status);

CREATE TABLE order_items (
    id                UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id          UUID    NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
    sku               TEXT    NOT NULL,
    -- Name is copied rather than joined to a product table, so an order keeps
    -- showing what was actually bought after a catalogue change.
    name              TEXT    NOT NULL,
    quantity          INTEGER NOT NULL CHECK (quantity > 0),
    unit_price_cents  BIGINT  NOT NULL CHECK (unit_price_cents >= 0)
);

CREATE INDEX idx_order_items_order_id ON order_items (order_id);
