# Login.py
# DEFINE FUNCTION hash_password(password)
#   GENERATE salt and HASH password
#   RETURN hashed password
# DEFINE FUNCTION check_password(hashed_password, user_password)
#   CHECK if user password matches hashed password
# DEFINE FUNCTION register()
#   DEFINE FUNCTION submit_registration(event=None)
#       GET name, username, password from entry fields
#       IF any field is empty, SHOW error
#       HASH password
#       TRY to WRITE name, username, hashed password to USER_FILE
#       SHOW success or error
#   CREATE registration_window with entry fields, labels, and Register button
# DEFINE FUNCTION login()
#   DEFINE FUNCTION submit_login(event=None)
#       GET username, password from entry fields
#       IF any field is empty, SHOW error
#       TRY to READ USER_FILE
#       FOR each row, CHECK username and password
#       IF valid, SHOW success, DESTROY main window, IMPORT and CALL encryptDecrypt.main()
#       SHOW error if invalid
#   CREATE login_window with entry fields, labels, and Login button
# DEFINE FUNCTION update_password()
#   DEFINE FUNCTION submit_update(event=None)
#       GET username, new_password from entry fields
#       IF any field is empty, SHOW error
#       TRY to READ and UPDATE USER_FILE
#       SHOW success or error
#   CREATE update_window with entry fields, labels, and Update button
# DEFINE FUNCTION admin_menu()
#   DEFINE FUNCTION admin_options()
#       DEFINE FUNCTION print_users()
#           TRY to READ and DISPLAY users from USER_FILE
#           SHOW error if needed
#       DEFINE FUNCTION delete_all_entries()
#           CLEAR USER_FILE and SHOW success
#       CREATE admin_window with buttons for print_users, delete_all_entries, Quit
#   ASK for admin password
#   IF correct, CALL admin_options()
#   ELSE SHOW error
# DEFINE FUNCTION main()
#   CREATE main window with buttons for Login, Register, Update Password, Admin Menu, Quit
# INITIALIZE and CONFIGURE main window
# CALL main() to start the application
# ENTER mainloop()


import csv
import bcrypt
from tkinter import *
from tkinter import messagebox, simpledialog
import tkinter.font as font

USER_FILE = 'users.csv'
ADMIN_PASSWORD = '062797'


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed


def check_password(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password)


def register():
    def submit_registration(event=None):
        name = entry_name.get().strip()
        username = entry_username.get().strip()
        password = entry_password.get().strip()

        if not name or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return

        hashed_password = hash_password(password)
        try:
            with open(USER_FILE, mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([name, username, hashed_password.decode()])
            messagebox.showinfo("Success", "Registration successful!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during registration: {e}")
        registration_window.destroy()

    registration_window = Toplevel(wn)
    registration_window.title("Register")
    registration_window.geometry("250x250")
    registration_window.configure(bg='gray63')
    Label(registration_window, text="Name:").pack(pady=5)
    entry_name = Entry(registration_window)
    entry_name.pack(pady=5)
    Label(registration_window, text="Username:").pack(pady=5)
    entry_username = Entry(registration_window)
    entry_username.pack(pady=5)
    Label(registration_window, text="Password:").pack(pady=5)
    entry_password = Entry(registration_window, show='*')
    entry_password.pack(pady=5)
    Button(registration_window, text="Register", bg='lawn green', command=submit_registration).pack(pady=20)
    registration_window.bind('<Return>', submit_registration)


def login():
    def submit_login(event=None):
        username = entry_username.get().strip()
        password = entry_password.get().strip()

        if not username or not password:
            messagebox.showerror("Error", "Both fields are required.")
            return

        try:
            with open(USER_FILE, mode='r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if len(row) < 3:
                        continue
                    if row[1] == username:
                        stored_hash = row[2].encode()  # Convert back to bytes
                        if check_password(stored_hash, password):
                            messagebox.showinfo("Success", "Login successful!")
                            wn.destroy()  # Close the main window
                            import encryptDecrypt  # Delay import
                            encryptDecrypt.main()  # Call the main function from encryptDecrypt
                            return
            messagebox.showerror("Error", "Invalid username or password.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during login: {e}")

    login_window = Toplevel(wn)
    login_window.configure(bg='gray63')
    login_window.title("Login")
    login_window.geometry("250x200")
    Label(login_window, text="Username:").pack(pady=5)
    entry_username = Entry(login_window)
    entry_username.pack(pady=5)
    Label(login_window, text="Password:").pack(pady=5)
    entry_password = Entry(login_window, show='*')
    entry_password.pack(pady=5)
    Button(login_window, text="Login", bg='lawn green', command=submit_login).pack(pady=20)
    login_window.bind('<Return>', submit_login)


def update_password():
    def submit_update(event=None):
        username = entry_username.get().strip()
        new_password = entry_new_password.get().strip()

        if not username or not new_password:
            messagebox.showerror("Error", "Both fields are required.")
            return

        try:
            rows = []
            user_found = False
            with open(USER_FILE, mode='r') as file:
                reader = csv.reader(file)
                for row in reader:
                    if row[1] == username:
                        user_found = True
                        hashed_new_password = hash_password(new_password)
                        row[2] = hashed_new_password.decode()
                        messagebox.showinfo("Success", "Password updated successfully!")
                    rows.append(row)
            if user_found:
                with open(USER_FILE, mode='w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerows(rows)
            else:
                messagebox.showerror("Error", "Username not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during password update: {e}")
        update_window.destroy()

    update_window = Toplevel(wn)
    update_window.configure(bg='gray63')
    update_window.title("Update Password")
    update_window.geometry("250x200")
    Label(update_window, text="Username:").pack(pady=5)
    entry_username = Entry(update_window)
    entry_username.pack(pady=5)
    Label(update_window, text="New Password:").pack(pady=5)
    entry_new_password = Entry(update_window, show='*')
    entry_new_password.pack(pady=5)
    Button(update_window, text="Update", bg='lawn green', command=submit_update).pack(pady=20)
    update_window.bind('<Return>', submit_update)


def admin_menu():
    def admin_options():
        def print_users():
            try:
                with open(USER_FILE, mode='r') as file:
                    reader = csv.reader(file)
                    users = "Name\tUsername\n" + "-" * 30 + "\n"
                    for row in reader:
                        if len(row) < 3:
                            continue
                        users += f"{row[0]}\t{row[1]}\n"
                    messagebox.showinfo("Users", users)
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while reading the user file: {e}")

        def delete_all_entries():
            try:
                with open(USER_FILE, mode='w', newline='') as file:
                    file.truncate()  # Clear the file content
                messagebox.showinfo("Success", "All entries deleted successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred while deleting the entries: {e}")

        admin_window = Toplevel(wn)
        admin_window.configure(bg='gray63')
        admin_window.title("Admin Menu")
        admin_window.geometry("250x200")
        Button(admin_window, text="Print Users", bg='lawn green', command=print_users).pack(pady=10)
        Button(admin_window, text="Delete All Entries", bg='dodger blue', command=delete_all_entries).pack(pady=10)
        Button(admin_window, text="Quit", bg='brown1', command=admin_window.destroy).pack(pady=10)

    admin_password = simpledialog.askstring("Admin Password", "Enter the admin password:", show='*')
    if admin_password == ADMIN_PASSWORD:
        admin_options()
    else:
        messagebox.showerror("Error", "Invalid admin password.")


def main():
    main_font = font.Font(family='Georgia', size=12, weight='bold')
    Button(wn, text="Login", bg='lawn green', font=main_font, command=login).pack(pady=10)
    Button(wn, text="Register", bg='dodger blue', font=main_font, command=register).pack(pady=10)
    Button(wn, text="Update Password", bg='orange', font=main_font, command=update_password).pack(pady=10)
    Button(wn, text="Admin Menu", font=main_font, command=admin_menu).pack(pady=10)
    Button(wn, text="Quit", bg='brown1', font=main_font, command=wn.quit).pack(pady=10)


wn = Tk()
wn.geometry("300x300")
wn.configure(bg='gray63')
wn.title("User Management System")

main()
wn.mainloop()
