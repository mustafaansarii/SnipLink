import sqlite3

DATABASE_FILE = "database.db"

def create_tables():
    conn = sqlite3.connect("database.db", check_same_thread=False)
    cur = conn.cursor()

    # Enable WAL mode to prevent database locking
    cur.execute("PRAGMA journal_mode=WAL;")

    # Create users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT
        )
    ''')

    # Create code_snippets table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS code_snippets (
            id TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            user_id INTEGER,
            created_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("Database initialized successfully!")


if __name__ == "__main__":
    create_tables()
