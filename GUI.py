import tkinter as tk
from tkinter import messagebox, scrolledtext
import sqlite3
from datetime import datetime
import threading

# Global state
monitoring = False
current_user = "admin"
db_lock = threading.Lock()

# SQLite setup
conn = sqlite3.connect("user_data.db", check_same_thread=False)
cursor = conn.cursor()

# Create tables if not exist
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL
                )''')

cursor.execute('''CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    timestamp TEXT,
                    event TEXT
                )''')

conn.commit()

# ---------------- GUI Utility Functions ---------------- #

def log_event(event):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with db_lock:
        cursor.execute("INSERT INTO history (username, timestamp, event) VALUES (?, ?, ?)",
                       (current_user, timestamp, event))
        conn.commit()

def update_gui_with_alert(msg):
    text_area.insert(tk.END, f"[ALERT] {msg}\n")
    text_area.see(tk.END)
    log_event(f"ALERT: {msg}")

def update_gui_with_response(msg):
    text_area.insert(tk.END, f"[!] {msg}\n")
    text_area.see(tk.END)
    log_event(f"RESPONSE: {msg}")

def update_gui_with_snort_alert(msg):
    text_area.insert(tk.END, f"[SNORT] {msg}\n")
    text_area.see(tk.END)
    log_event(f"SNORT ALERT: {msg}")

def update_gui_with_zeek_alert(msg):
    text_area.insert(tk.END, f"[ZEEK] {msg}\n")
    text_area.see(tk.END)
    log_event(f"ZEEK ALERT: {msg}")

def update_gui_with_normal(msg):
    text_area.insert(tk.END, f"[NORMAL] {msg}\n")
    text_area.see(tk.END)
    log_event(f"NORMAL: {msg}")

def clear_output():
    text_area.delete(1.0, tk.END)

def log_start():
    text_area.insert(tk.END, "[INFO] Starting packet monitoring...\n")
    text_area.see(tk.END)
    log_event("Started packet monitoring.")

def log_stop():
    text_area.insert(tk.END, "[INFO] Monitoring stopped.\n")
    text_area.see(tk.END)
    log_event("Stopped packet monitoring.")

# ---------------- GUI Main Window ---------------- #

def build_gui():
    global text_area, start_btn, stop_btn, root
    root = tk.Tk()
    root.title("Network Security Monitoring")

    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30)
    text_area.pack(padx=10, pady=10)

    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    start_btn = tk.Button(button_frame, text="Start Detection", bg="green", fg="white", command=start_detection)
    start_btn.pack(side=tk.LEFT, padx=5)

    stop_btn = tk.Button(button_frame, text="Stop Monitoring", bg="red", fg="white", command=stop_detection)
    stop_btn.pack(side=tk.LEFT, padx=5)

    log_start()
    root.mainloop()

# ---------------- Login System ---------------- #

def show_login_window():
    login_window = tk.Tk()
    login_window.title("Login")

    tk.Label(login_window, text="Username:").grid(row=0, column=0, padx=10, pady=5)
    username_entry = tk.Entry(login_window)
    username_entry.grid(row=0, column=1, padx=10, pady=5)

    tk.Label(login_window, text="Password:").grid(row=1, column=0, padx=10, pady=5)
    password_entry = tk.Entry(login_window, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)

    def attempt_login():
        global current_user
        username = username_entry.get()
        password = password_entry.get()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        if cursor.fetchone():
            current_user = username
            login_window.destroy()
            build_gui()
        else:
            messagebox.showerror("Login Failed", "Invalid credentials!")

    def register_user():
        reg_window = tk.Toplevel(login_window)
        reg_window.title("Register New User")

        tk.Label(reg_window, text="New Username:").grid(row=0, column=0, padx=10, pady=5)
        new_user_entry = tk.Entry(reg_window)
        new_user_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(reg_window, text="New Password:").grid(row=1, column=0, padx=10, pady=5)
        new_pass_entry = tk.Entry(reg_window, show="*")
        new_pass_entry.grid(row=1, column=1, padx=10, pady=5)

        def save_new_user():
            new_user = new_user_entry.get()
            new_pass = new_pass_entry.get()
            if new_user and new_pass:
                try:
                    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_user, new_pass))
                    conn.commit()
                    messagebox.showinfo("Success", "User registered successfully!")
                    reg_window.destroy()
                except sqlite3.IntegrityError:
                    messagebox.showerror("Error", "Username already exists.")
            else:
                messagebox.showwarning("Input Error", "All fields are required.")

        tk.Button(reg_window, text="Register", command=save_new_user).grid(row=2, columnspan=2, pady=10)

    tk.Button(login_window, text="Login", command=attempt_login).grid(row=2, column=0, pady=10)
    tk.Button(login_window, text="Register", command=register_user).grid(row=2, column=1, pady=10)

    login_window.mainloop()

# ---------------- Start/Stop Detection ---------------- #

def start_detection():
    global monitoring
    if not monitoring:
        monitoring = True
        import threading
        from Main import start_sniffing
        threading.Thread(target=start_sniffing, daemon=True).start()

def stop_detection():
    global monitoring
    if monitoring:
        monitoring = False
        log_stop()

# ---------------- Launch Login ---------------- #
show_login_window()
