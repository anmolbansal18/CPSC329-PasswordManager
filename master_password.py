import sqlite3
import hashlib
import uuid
from tkinter import Tk, Label, Entry, Button, messagebox


def hash_password(input):
    return hashlib.sha256(input.encode('utf-8')).hexdigest()


def create_masterpassword_table(db):
    cursor = db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS masterpassword(
        id INTEGER PRIMARY KEY,
        password TEXT NOT NULL,
        recoveryKey TEXT NOT NULL);
    """)


def reset_password_screen(db):
    def reset_password():
        recovery_key = hash_password(recovery_key_entry.get())
        cursor = db.cursor()
        cursor.execute(
            "SELECT * FROM masterpassword WHERE recoveryKey = ?", (recovery_key,))
        if cursor.fetchone():
            window.destroy()
            first_time_screen(db)
        else:
            messagebox.showerror("Error", "Invalid Recovery Key")

    window = Tk()
    window.title("Reset Master Password")

    Label(window, text="Enter Recovery Key").grid(row=0, column=0, pady=10)
    recovery_key_entry = Entry(window, show="*", width=20)
    recovery_key_entry.grid(row=1, column=0)

    Button(window, text="Reset Password", command=reset_password).grid(
        row=2, column=0, pady=10)

    window.mainloop()


def first_time_screen(db):
    def save_password():
        if password_entry.get() == confirm_password_entry.get():
            hashed_password = hash_password(password_entry.get())
            recovery_key = str(uuid.uuid4().hex)
            hashed_recovery_key = hash_password(recovery_key)

            cursor = db.cursor()
            cursor.execute("DELETE FROM masterpassword")
            cursor.execute("INSERT INTO masterpassword(password, recoveryKey) VALUES(?, ?)",
                           (hashed_password, hashed_recovery_key))
            db.commit()

            messagebox.showinfo("Recovery Key", f"Your recovery key is: {
                                recovery_key}\nSave this key to recover your account.")
            window.destroy()
            launch_password_manager()

        else:
            messagebox.showerror("Error", "Passwords do not match. Try again.")

    window = Tk()
    window.title("Set Master Password")

    Label(window, text="Set Master Password").grid(row=0, column=0, pady=10)
    password_entry = Entry(window, show="*", width=20)
    password_entry.grid(row=1, column=0)

    Label(window, text="Re-enter Password").grid(row=2, column=0, pady=10)
    confirm_password_entry = Entry(window, show="*", width=20)
    confirm_password_entry.grid(row=3, column=0)

    Button(window, text="Save", command=save_password).grid(
        row=4, column=0, pady=10)

    window.mainloop()


def login_screen(db):
    def check_password():
        cursor = db.cursor()
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1")
        master_password_record = cursor.fetchone()

        if master_password_record and hash_password(password_entry.get()) == master_password_record[1]:
            window.destroy()
            launch_password_manager()
        else:
            messagebox.showerror("Error", "Incorrect Master Password")

    def reset_password_wrapper():
        window.destroy()
        reset_password_screen(db)

    window = Tk()
    window.title("Login")

    Label(window, text="Enter Master Password").grid(row=0, column=0, pady=10)
    password_entry = Entry(window, show="*", width=20)
    password_entry.grid(row=1, column=0)

    Button(window, text="Submit", command=check_password).grid(
        row=2, column=0, pady=10)
    Button(window, text="Reset Password", command=reset_password_wrapper).grid(
        row=3, column=0, pady=10)

    window.mainloop()


def launch_password_manager():
    from password_manager import root_window  # Ensure this import works correctly
    from db_operation import DbOperations  # Ensure this import works correctly

    db_class = DbOperations()
    root = Tk()
    password_manager_app = root_window(root, db_class)
    root.mainloop()


def main():
    with sqlite3.connect('password_records.db') as db:
        create_masterpassword_table(db)
        cursor = db.cursor()
        cursor.execute('SELECT * FROM masterpassword')
        if cursor.fetchone():
            login_screen(db)
        else:
            first_time_screen(db)


if __name__ == "__main__":
    main()
