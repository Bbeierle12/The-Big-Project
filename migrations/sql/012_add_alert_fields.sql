-- Add tracking fields to alerts table
ALTER TABLE alerts ADD COLUMN source_event_id TEXT;
ALTER TABLE alerts ADD COLUMN device_id TEXT;
ALTER TABLE alerts ADD COLUMN raw_data TEXT;
ALTER TABLE alerts ADD COLUMN first_seen TEXT;
ALTER TABLE alerts ADD COLUMN last_seen TEXT;

-- Backfill first_seen/last_seen from created_at for existing rows
UPDATE alerts SET first_seen = created_at WHERE first_seen IS NULL;
UPDATE alerts SET last_seen = updated_at WHERE last_seen IS NULL;
