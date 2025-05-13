-- Create table for scanner configurations
CREATE TABLE IF NOT EXISTS scanner_configurations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanner_id VARCHAR(36) NOT NULL,
    client_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    configuration JSON NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    html_snippet TEXT,
    status VARCHAR(50) DEFAULT 'active',
    version VARCHAR(10) DEFAULT '1.0',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES clients(id),
    FOREIGN KEY (scanner_id) REFERENCES deployed_scanners(id)
);

-- Create index for faster lookups
CREATE INDEX idx_scanner_api_key ON scanner_configurations(api_key);
