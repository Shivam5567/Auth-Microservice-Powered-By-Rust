-- Seed the first-party downstream service.
--
-- Services that ship as part of this platform are known up front, so they are
-- seeded rather than added by hand. Anything else -- a partner integration, a
-- new internal service -- gets added through the admin panel.
--
-- Removing this row from the registry is the off switch: doing so immediately
-- invalidates every session bound to orders-service and stops new ones being
-- created, which is what you want if the service is compromised.

INSERT INTO services (name, description, scopes)
VALUES (
    'orders-service',
    'Storefront and checkout for the example e-commerce application',
    ARRAY['orders:read', 'orders:write']
);
