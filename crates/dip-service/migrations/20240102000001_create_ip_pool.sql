CREATE TABLE IF NOT EXISTS ip_pool (
    id UUID PRIMARY KEY,
    ip TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'available',
    reserved_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ip_pool_status ON ip_pool(status);
CREATE INDEX idx_ip_pool_reserved_until ON ip_pool(reserved_until);

INSERT INTO ip_pool (id, ip) VALUES
    (gen_random_uuid(), '192.168.1.100'),
    (gen_random_uuid(), '192.168.1.101'),
    (gen_random_uuid(), '192.168.1.102'),
    (gen_random_uuid(), '192.168.1.103'),
    (gen_random_uuid(), '192.168.1.104');