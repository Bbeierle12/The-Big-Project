-- Add service, device_ip, status, and references fields to vulnerabilities table
ALTER TABLE vulnerabilities ADD COLUMN service TEXT;
ALTER TABLE vulnerabilities ADD COLUMN device_ip TEXT;
ALTER TABLE vulnerabilities ADD COLUMN status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE vulnerabilities ADD COLUMN references_json TEXT;
