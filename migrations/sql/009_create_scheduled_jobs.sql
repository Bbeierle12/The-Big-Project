-- Scheduled job definitions
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id TEXT PRIMARY KEY NOT NULL,
    trigger_type TEXT NOT NULL,
    trigger_args TEXT NOT NULL DEFAULT '{}',
    task_type TEXT NOT NULL,
    task_params TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_enabled ON scheduled_jobs(enabled);
CREATE INDEX IF NOT EXISTS idx_scheduled_jobs_task_type ON scheduled_jobs(task_type);
