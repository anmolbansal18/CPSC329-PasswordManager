from tkinter import Tk, Label, Entry, Frame, END, Toplevel, PhotoImage, Button, messagebox
from tkinter import ttk
from db_operation import DbOperations
import re
import random
import string


class root_window:
    def __init__(self, root, db):

        self.db = db
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("1350x600+40+40")

        label_bg_color = 'purple'
        label_fg_color = 'white'

        head_title = Label(self.root, text="Password Manager", width=40,
                           bg=label_bg_color, font=("Arial", 20), padx=10, pady=10, justify='center',
                           anchor="center")
        head_title.grid(columnspan=4, padx=140, pady=20)

        self.crud_frame = Frame(
            self.root, highlightbackground="black", highlightthickness=1, padx=10, pady=30)
        self.crud_frame.grid()
        self.create_entry_labels()
        self.create_entry_boxes()
        self.create_crud_buttons()
        self.search_entry = Entry(
            self.crud_frame, width=30, font=("Arial", 12))
        self.search_entry.grid(row=self.row_no, column=self.col_no)
        self.col_no += 1

        ttk.Button(self.crud_frame, text="Search", width=20).grid(
            row=self.row_no, column=self.col_no, padx=5, pady=5)
        self.col_no += 1

        # Adding the "Generate Password" button
        ttk.Button(self.crud_frame, text="Generate Password", width=20,
                   command=self.generate_password).grid(row=self.row_no,
                                                        column=self.col_no,
                                                        padx=5, pady=5)

        self.create_records_tree()

    def create_entry_labels(self):
        self.col_no, self.row_no = 0, 0
        labels_info = ('ID', 'Website', 'Username', 'Password')
        for label_info in labels_info:
            Label(self.crud_frame, text=label_info, bg='grey', fg="white",
                  font=("Arial", 12), padx=5, pady=2).grid(row=self.row_no, column=self.col_no, padx=5, pady=2)
            self.col_no += 1

    def create_entry_boxes(self):
        self.row_no += 1
        self.entry_boxes = []
        self.col_no = 0

        for i in range(4):
            show = "" if i != 3 else "*"
            entry_box = Entry(self.crud_frame, width=20, background="lightgrey", font=(
                "Arial", 12), show=show, foreground="black")
            entry_box.grid(row=self.row_no, column=self.col_no,
                           padx=5, pady=2, sticky="ew")

            if i == 3:  # Password entry box
                self.password_entry = entry_box
                entry_box.bind('<KeyRelease>', self.check_password_strength)

                # Show Password Button
                self.show_password_btn = Button(self.crud_frame, text="Show")
                self.show_password_btn.grid(
                    row=self.row_no, column=self.col_no+1, padx=1, pady=1)
                self.show_password_btn.bind(
                    "<ButtonPress>", lambda event: self.toggle_password_visibility(True))
                self.show_password_btn.bind(
                    "<ButtonRelease>", lambda event: self.toggle_password_visibility(False))

                # Password Strength Label
                self.password_strength_label = Label(self.crud_frame, text="", font=(
                    "Arial", 14, "bold"), bg="white", fg="black")
                self.password_strength_label.grid(
                    row=self.row_no, column=self.col_no+2, padx=1, pady=1, sticky="ew")

            self.col_no += 1
            self.entry_boxes.append(entry_box)

        # Positioning the password criteria text
        password_criteria_text = (
            "Strong Password Criteria:\n"
            "- At least 8 characters\n"
            "- Mix of uppercase and lowercase letters\n"
            "- Mix of letters and numbers\n"
            "- At least one special characters (e.g., !@#$%^&*+-?)"
        )
        self.password_criteria_label = Label(self.crud_frame, text=password_criteria_text, font=(
            "Arial", 13), fg="red", justify="left")
        self.password_criteria_label.grid(
            row=self.row_no+1, column=4, padx=5, pady=5, sticky="w")

    def toggle_password_visibility(self, show: bool):
        """Toggle the visibility of the password in the entry box."""
        if show:
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def check_password_strength(self, event=None):
        password = self.entry_boxes[3].get()
        strength = 'WEAK'
        color = 'red'  # Default color for weak password

        if (len(password) >= 8 and re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and re.search(r"[0-9]", password) and
                re.search(r"[!@#$%^*+=\-?]", password)):
            strength = 'STRONG'
            color = 'green'  # Green color for strong password
        elif len(password) >= 8:
            strength = 'MEDIUM'
            color = 'orange'  # Orange color for medium password

        self.password_strength_label.config(
            text=strength, bg=color, fg="white")

    def create_crud_buttons(self):
        self.row_no += 1
        self.col_no = 0
        buttons_info = (('Save', self.save_record), ('Update', self.update_record),
                        ('Delete', self.delete_record), ('Copy Password',
                                                         self.copy_password),
                        ('Show All Records', self.show_records))
        for btn_info in buttons_info:
            if btn_info[0] in ['Show All Records', 'Generate Password']:
                self.row_no += 1
                self.col_no = 0

            ttk.Button(self.crud_frame, text=btn_info[0], width=20,
                       command=btn_info[1]).grid(row=self.row_no,
                                                 column=self.col_no,
                                                 padx=5, pady=10)
            self.col_no += 1

    def create_records_tree(self):
        columns = ('ID', 'Website', 'Username', 'Password')
        self.records_tree = ttk.Treeview(
            self.root, columns=columns, show='headings')
        self.records_tree.heading('ID', text="ID")
        self.records_tree.heading('Website', text="Website Name")
        self.records_tree.heading('Username', text="Username")
        self.records_tree.heading('Password', text="Password")
        self.records_tree['displaycolumns'] = ('Website', 'Username')

        self.records_tree.bind('<<TreeviewSelect>>', self.item_selected)
        self.records_tree.grid()

    def item_selected(self, event):
        for selected_item in self.records_tree.selection():
            item = self.records_tree.item(selected_item)
            record = item['values']
            for entry_box, item in zip(self.entry_boxes, record):
                entry_box.delete(0, END)
                entry_box.insert(0, item)

    # Placeholder function for the Generate Password button
    def generate_password(self):
        # Define the criteria for a strong password
        password_length = 12
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        digits = string.digits
        special = string.punctuation

        # Ensure the password contains at least two special characters and one character of each other type
        password = [
            random.choice(lower),
            random.choice(upper),
            random.choice(digits),
            random.choice(special),
            random.choice(special)  # Add an extra special character
        ]

        # Fill the rest of the password length with a random mix of character types
        for _ in range(password_length - 5):
            password.append(random.choice(lower + upper + digits + special))

        # Shuffle the password list to avoid predictable patterns
        random.shuffle(password)

        # Convert the list of characters into a string
        password = ''.join(password)

        # Update the password entry box with the generated password
        self.password_entry.delete(0, END)
        self.password_entry.insert(0, password)

        # Directly update the strength label as 'Strong'
        self.check_password_strength()

    def save_record(self):
        website = self.entry_boxes[1].get()
        username = self.entry_boxes[2].get()
        password = self.entry_boxes[3].get()

        data = {'website': website, 'username': username, 'password': password}
        self.db.create_record(data)
        self.show_records()

    def update_record(self):
        ID = self.entry_boxes[0].get()
        website = self.entry_boxes[1].get()
        username = self.entry_boxes[2].get()
        password = self.entry_boxes[3].get()

        data = {'ID': ID, 'website': website,
                'username': username, 'password': password}
        self.db.update_record(data)
        self.show_records()

    def delete_record(self):
        ID = self.entry_boxes[0].get()
        self.db.delete_record(ID)
        self.show_records()

    def show_records(self):
        for item in self.records_tree.get_children():
            self.records_tree.delete(item)
        records_list = self.db.show_records()
        for record in records_list:
            self.records_tree.insert('', END, values=(
                record[0], record[3], record[4], record[5]))

    def create_records_tree(self):
        columns = ('ID', 'Website', 'Username', 'Password')
        self.records_tree = ttk.Treeview(
            self.root, columns=columns, show='headings')
        self.records_tree.heading('ID', text="ID")
        self.records_tree.heading('Website', text="Website Name")
        self.records_tree.heading('Username', text="Username")
        self.records_tree.heading('Password', text="Password")
        self.records_tree['displaycolumns'] = ('Website', 'Username')

        self.records_tree.bind('<<TreeviewSelect>>', self.item_selected)
        self.records_tree.grid()

    def item_selected(self, event):
        for selected_item in self.records_tree.selection():
            item = self.records_tree.item(selected_item)
            record = item['values']
            for entry_box, item in zip(self.entry_boxes, record):
                entry_box.delete(0, END)
                entry_box.insert(0, item)

    # Copy to Clipboard
    def copy_password(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.entry_boxes[3].get())
        message = "Password Copied"
        title = "Copy"
        if self.entry_boxes[3].get() == "":
            message = "Box is Empty"
            title = "Error"
        self.showmessage(title, message)

    def showmessage(self, title_box: str = None, message: str = None):
        TIME_TO_WAIT = 900  # in milliseconds
        root = Toplevel(self.root)
        background = 'green'
        if title_box == "Error":
            background = "red"
        root.geometry('200x30+600+200')
        root.title(title_box)
        Label(root, text=message, background=background, font=("Arial", 15),
              fg='white').pack(padx=4, pady=2)

        try:
            root.after(TIME_TO_WAIT, root.destroy)
        except Exception as e:
            print("Error occurred", e)


if __name__ == "__main__":
    # CREATE TABLE IF DOESN'T EXIST
    db_class = DbOperations()
    db_class.create_table()
    # CREATE TKINTER WINDOW
    root = Tk()
    root_class = root_window(root, db_class)
    root.mainloop()
