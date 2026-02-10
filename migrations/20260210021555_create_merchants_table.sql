CREATE TABLE merchants (
    -- Technical
    id SERIAL PRIMARY KEY,

    -- Salla data (auto-filled from OAuth + user/info)
    merchant_id VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Business rules (you control these)
    balance DECIMAL(10, 2) DEFAULT 0.00,
    plan VARCHAR(50) DEFAULT 'pay_as_you_go',
    total_scans INT DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_merchant_id ON merchants(merchant_id);
