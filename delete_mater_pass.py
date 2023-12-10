import sqlite3


def delete_master_password(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM masterpassword")
        conn.commit()
        print("Master password deleted successfully.")
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    # Adjust the path if your database is located elsewhere
    db_path = 'password_records.db'
    delete_master_password(db_path)
