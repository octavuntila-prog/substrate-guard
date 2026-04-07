-- Minimal tables for `python -m substrate_guard.audit` (SUBSTRATE-compatible shape).
-- Loaded automatically when using docker-compose.stack.yml (initdb).

CREATE TABLE IF NOT EXISTS pipeline_traces (
    id BIGSERIAL PRIMARY KEY,
    trace_id TEXT,
    pipeline_run_id TEXT,
    step_index INT,
    agent_id INT,
    agent_name TEXT,
    status TEXT,
    model_used TEXT,
    input_summary TEXT,
    output_summary TEXT,
    tokens_in INT,
    tokens_out INT,
    cost_usd DOUBLE PRECISION,
    duration_ms INT,
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    confidence DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS agent_runs (
    id BIGSERIAL PRIMARY KEY,
    agent_id INT,
    agent_name TEXT,
    status TEXT,
    duration_ms INT,
    confidence DOUBLE PRECISION,
    error TEXT,
    input_summary TEXT,
    output_summary TEXT,
    trace_id TEXT,
    created_at TIMESTAMPTZ
);
