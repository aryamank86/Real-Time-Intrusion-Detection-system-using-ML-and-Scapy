import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT)''')

    c.execute('''CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    timestamp TEXT,
                    event TEXT)''')
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def validate_user(username, password):
    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
    user = c.fetchone()
    conn.close()
    return user is not None

def log_event(username, event):
    conn = sqlite3.connect('monitoring.db')
    c = conn.cursor()
    c.execute("INSERT INTO history (username, timestamp, event) VALUES (?, ?, ?)", 
              (username, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event))
    conn.commit()
    conn.close()
