CREATE TABLE IF NOT EXISTS assignments (
    id UUID PRIMARY KEY,
    blinded_token_hash TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_assignments_token_hash ON assignments(blinded_token_hash);
CREATE INDEX idx_assignments_ip ON assignments(ip);