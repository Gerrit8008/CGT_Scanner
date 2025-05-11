-- Main admin database schema
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT DEFAULT 'client',
    full_name TEXT,
    created_at TEXT,
    last_login TEXT,
    active INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    business_name TEXT NOT NULL,
    business_domain TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    contact_phone TEXT,
    subscription_level TEXT DEFAULT 'basic',
    subscription_status TEXT DEFAULT 'active',
    subscription_start TEXT,
    subscription_end TEXT,
    database_name TEXT UNIQUE,  -- Store the name of client's specific database
    created_at TEXT,
    created_by INTEGER,
    active INTEGER DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS deployed_scanners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    scanner_name TEXT NOT NULL,
    subdomain TEXT UNIQUE,
    api_key TEXT UNIQUE,
    status TEXT DEFAULT 'active',
    created_at TEXT,
    last_active TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);
