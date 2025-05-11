-- Template for individual client databases
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id TEXT NOT NULL,
    scan_timestamp TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    results TEXT,  -- JSON formatted results
    report_path TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id TEXT NOT NULL,
    name TEXT,
    email TEXT NOT NULL,
    company TEXT,
    phone TEXT,
    source TEXT,
    status TEXT DEFAULT 'new',
    created_at TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS scan_configurations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id TEXT NOT NULL,
    name TEXT NOT NULL,
    configuration TEXT NOT NULL,  -- JSON formatted configuration
    is_default BOOLEAN DEFAULT 0,
    created_at TEXT,
    updated_at TEXT
);

-- Indexes for better performance
CREATE INDEX idx_scans_scanner ON scans(scanner_id);
CREATE INDEX idx_leads_scanner ON leads(scanner_id);
CREATE INDEX idx_leads_email ON leads(email);
