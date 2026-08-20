import sqlite3

conn = sqlite3.connect("security.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_value TEXT UNIQUE,
    token_type TEXT,
    is_active INTEGER DEFAULT 1
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    source_ip TEXT,
    used_token TEXT,
    incident_type TEXT,
    details TEXT,
    severity TEXT DEFAULT 'Low',
    mitre_technique TEXT DEFAULT 'N/A',
    review_status TEXT DEFAULT 'unreviewed',
    ai_explanation TEXT DEFAULT 'N/A'
)
""")

cursor.execute("DELETE FROM tokens")

cursor.execute("INSERT INTO tokens (token_value, token_type, is_active) VALUES (?, ?, ?)",
               ("real-key-abc123", "REAL", 1))
cursor.execute("INSERT INTO tokens (token_value, token_type, is_active) VALUES (?, ?, ?)",
               ("canary-key-xyz789", "CANARY", 1))

conn.commit()
conn.close()

print("Database setup complete.")
