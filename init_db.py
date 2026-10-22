import sqlite3, bcrypt

conn = sqlite3.connect("app.db")
conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
)
""")
pwd = bcrypt.hashpw(b"password123", bcrypt.gensalt())
conn.execute("INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)", ("alice", pwd))
conn.commit()
conn.close()