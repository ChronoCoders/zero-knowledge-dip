CREATE TABLE IF NOT EXISTS subscriptions (
    id UUID PRIMARY KEY,
    subscription_id TEXT NOT NULL UNIQUE,
    redeemed BOOLEAN NOT NULL DEFAULT false,
    version INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscriptions_subscription_id ON subscriptions(subscription_id);
CREATE INDEX idx_subscriptions_redeemed ON subscriptions(redeemed);