CREATE TABLE IF NOT EXISTS soc_cases (
    case_id TEXT PRIMARY KEY,

    status TEXT NOT NULL,

    alert_id TEXT,

    state JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_soc_cases_status
ON soc_cases (status);

CREATE INDEX IF NOT EXISTS idx_soc_cases_alert_id
ON soc_cases (alert_id);

CREATE INDEX IF NOT EXISTS idx_soc_cases_updated_at
ON soc_cases (updated_at DESC);