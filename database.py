import sqlite3

conn = sqlite3.connect("users.db")

cursor = conn.cursor()

# USERS TABLE
cursor.execute("""

CREATE TABLE IF NOT EXISTS users(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    email TEXT,

    password TEXT,

    joined_date TEXT

)

""")

# SCAN HISTORY TABLE
cursor.execute("""

CREATE TABLE IF NOT EXISTS scan_history(

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT,

    website_url TEXT,

    threat_level TEXT,

    security_score TEXT,

    scan_date TEXT

)

""")

conn.commit()

conn.close()

print("Database Created Successfully")