import tkinter as tk
from tkinter import messagebox
from database import validate_user, init_db

def launch_login(start_main_gui):
    def try_login():
        username = user_entry.get()
        password = pass_entry.get()
        if validate_user(username, password):
            login_win.destroy()
            start_main_gui(username)
        else:
            messagebox.showerror("Login Failed", "Invalid username or password.")

    init_db()
    login_win = tk.Tk()
    login_win.title("Login")

    tk.Label(login_win, text="Username").grid(row=0, column=0)
    user_entry = tk.Entry(login_win)
    user_entry.grid(row=0, column=1)

    tk.Label(login_win, text="Password").grid(row=1, column=0)
    pass_entry = tk.Entry(login_win, show="*")
    pass_entry.grid(row=1, column=1)

    tk.Button(login_win, text="Login", command=try_login).grid(row=2, columnspan=2)

    login_win.mainloop()
