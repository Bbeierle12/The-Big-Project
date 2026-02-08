-- Add os_version and notes fields to devices table
ALTER TABLE devices ADD COLUMN os_version TEXT;
ALTER TABLE devices ADD COLUMN notes TEXT;
