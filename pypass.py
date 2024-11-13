from tkinter import *
from tkinter import simpledialog
from tkinter import messagebox
import pickle
import random
from cryptography.fernet import Fernet

class CustomDialog(Toplevel):
  def __init__(self, master, title="", message="", width=300, height=150, bg="white"):
    super().__init__(master)
    self.title(title)
    self.geometry(f"{width}x{height}")
    self.configure(bg=bg)
    self.center_window(width, height)
    
    # Prevent interaction with the main window
    self.transient(master)
    self.grab_set()

    # Message Label
    self.message = Label(self, text=message, font=("Verdana", 10), bg=bg, wraplength=width - 20)
    self.message.pack(pady=10)

    # Button Frame
    self.button_frame = Frame(self, bg=bg)
    self.button_frame.pack(pady=10)

  def center_window(self, width, height):
    x = (self.winfo_screenwidth() // 2) - (width // 2)
    y = (self.winfo_screenheight() // 2) - (height // 2)
    self.geometry(f"{width}x{height}+{x}+{y}")

  def add_button(self, text, command, font=("Orbitron", 9, "bold"), bg="#ffd166", fg="black"):
    button = Button(self.button_frame, text=text, command=command, font=font, bg=bg, fg=fg, relief="solid", width=10)
    button.pack(side=LEFT, padx=5)

class SearchDialog(CustomDialog):
  def __init__(self, master):
    super().__init__(master, title="Search Password", message="Enter the website name to search:")
    self.result = None

    # Entry for website name
    self.entry = Entry(self, font=("Verdana", 10), bd=1, relief="solid")
    self.entry.pack(pady=5)
    self.entry.focus_set()

    # Buttons
    self.add_button("Search", self.search)
    self.add_button("Cancel", self.cancel)

  def search(self):
    self.result = self.entry.get().strip()
    self.destroy()

  def cancel(self):
    self.result = None
    self.destroy()

class InfoDialog(CustomDialog):
  def __init__(self, master, title, message, width=300, height=150):
    super().__init__(master, title=title, message=message, width=width, height=height)

    # OK button
    self.add_button("OK", self.ok)

  def ok(self):
    self.destroy()

class DeleteDialog(CustomDialog):
  def __init__(self, master):
    super().__init__(master, title="Delete Password", message="Enter the website name to delete:")
    self.result = None

    # Entry for website name
    self.entry = Entry(self, font=("Verdana", 10), bd=1, relief="solid")
    self.entry.pack(pady=5)
    self.entry.focus_set()

    # Buttons
    self.add_button("Delete", self.delete)
    self.add_button("Cancel", self.cancel)

  def delete(self):
    self.result = self.entry.get().strip()
    self.destroy()

  def cancel(self):
    self.result = None
    self.destroy()

class PasswordManager(object):
  def __init__(self, master, filename="passwords.pkl", key_file="secret.key"):
    self.master = master
    self.filename = filename
    self.key_file = key_file
    self.key = self.load_key()
    self.cipher = Fernet(self.key)
    self.passwords = self.load_passwords()

  def load_key(self):
    try:
      # Load the key from the key file if it exists
      with open(self.key_file, "rb") as key_file:
        return key_file.read()
    except FileNotFoundError:
      # If the key file doesn't exist, generate a new key and save it
      key = Fernet.generate_key()
      with open(self.key_file, "wb") as key_file:
        key_file.write(key)
      return key

  def encrypt_password(self, password):
    # Encrypt the password
    return self.cipher.encrypt(password.encode()).decode()

  def decrypt_password(self, encrypted_password):
    # Decrypt the password
    return self.cipher.decrypt(encrypted_password.encode()).decode()

  def add_password(self, website, username, password):
    encrypted_password = self.encrypt_password(password)
    self.passwords.append({"Website": website, "Username": username, "Password": encrypted_password})
    self.save_passwords()

    InfoDialog(self.master, title="Password Added!", message=f"Password for {website} added successfully.")

  def search_password(self, website):
    for pw in self.passwords:
      if pw["Website"] == website:
        pw_copy = pw.copy()
        pw_copy["Password"] = self.decrypt_password(pw["Password"])
        return pw_copy
    return None

  def delete_password(self, website):
    initial_length = len(self.passwords)
    self.passwords = [pw for pw in self.passwords if pw["Website"] != website]
    if len(self.passwords) < initial_length:
      self.save_passwords()
      return True
    return False

  def save_passwords(self):
    try:
      with open(self.filename, "wb") as file:
        pickle.dump(self.passwords, file)
    except Exception as e:
      self.window = Toplevel(self.master)
      self.window.title("PyPass Password Manager")
      self.window.config(padx=20, pady=20, bg="white")
      InfoDialog(self.window, title="Error", message=f"An error occurred while saving: {e}")

  def load_passwords(self):
    try:
      with open(self.filename, "rb") as file:
        passwords = pickle.load(file)
        # Decrypt passwords when loading (for displaying purposes)
        for pw in passwords:
          pw["Password"] = self.encrypt_password(self.decrypt_password(pw["Password"]))
        return passwords
    except FileNotFoundError:
      return []
    except Exception as e:
      self.window = Toplevel(self.master)
      self.window.title("PyPass Password Manager")
      self.window.config(padx=20, pady=20, bg="white")
      InfoDialog(self.window, title="Error!", message=f"An error occurred while loading passwords: {e}")
      return []

class PyPass(object):
  def __init__(self):
    self.window = Tk()
    self.window.title("PyPass Password Manager")
    self.window.config(padx=20, pady=20, bg="white")
    self.password_manager = PasswordManager(self.window)

    logo_img = PhotoImage(file="logo.png")
    canvas = Canvas(self.window, width=200, height=200, bg="white", highlightthickness=0, bd=0)
    canvas.create_image(100, 100, image=logo_img)
    canvas.grid(row=0, column=1)

    #Labels
    website_lbl = Label(text="Website", bg="white", font=("Verdana", 9, "bold"))
    website_lbl.grid(row=1, column=0, pady=10, sticky="e")
    username_lbl = Label(text="Username / Email", bg="white", font=("Verdana", 9, "bold"))
    username_lbl.grid(row=2, column=0, sticky="e")
    pw_lbl = Label(text="Password", bg="white", font=("Verdana", 9, "bold"))
    pw_lbl.grid(row=3, column=0, sticky="e")

    #Entries
    self.website_entry = Entry(width=43, bd=1, relief="solid", font=("Verdana", 10, "bold"))
    self.website_entry.grid(row=1, column=1, pady=10, columnspan=2, ipady=3)
    self.username_entry = Entry(width=43, bd=1, relief="solid", font=("Verdana", 10, "bold"))
    self.username_entry.grid(row=2, column=1, columnspan=2, ipady=3)
    self.pw_entry = Entry(width=33, bd=1, relief="solid", font=("Verdana", 10, "bold"))
    self.pw_entry.grid(row=3, column=1, pady=10, ipady=3)

    #Buttons
    generate_btn = Button(text="Generate", bd=1, relief="solid", font=("Orbitron", 9, "bold"), bg="white", command=self.generate)
    generate_btn.grid(row=3, column=2, padx=5)
    add_button = Button(text="Add", bd=1, width=43, font=("Orbitron", 9, "bold"), bg="#003049", fg="white", activebackground="#00263A", activeforeground="white", relief="solid", pady=5, command=self.add)
    add_button.grid(row=4, column=1, columnspan=2, padx=2)

    see_btn = Button(text="See all passwords", bd=1, relief="solid", bg="#ffd166", activebackground="#E6B854", font=("Orbitron", 9, "bold"), command=self.password_list)
    see_btn.grid(row=5, column=1, pady=10, padx=2, sticky="ew")
    search_btn = Button(text="Search", width=14, bd=1, relief="solid", font=("Orbitron", 9, "bold"), bg="#ffd166", activebackground="#E6B854", command=self.search)
    search_btn.grid(row=5, column=0, pady=10, padx=2, sticky="ew")
    delete_btn = Button(text="Delete", bd=1, relief="solid", font=("Orbitron", 9, "bold"), bg="#ffd166", activebackground="#E6B854", command=self.delete)
    delete_btn.grid(row=5, column=2, pady=10, padx=2, sticky="ew")

    self.window.mainloop()

  def add(self):
    website = self.website_entry.get()
    username = self.username_entry.get()
    password = self.pw_entry.get()

    if not website or not username or not password:
      InfoDialog(self.window, title="Invalid Input", message="Please Fill in All Fields.")
    else:
      self.password_manager.add_password(website, username, password)
      self.website_entry.delete(0, END)
      self.username_entry.delete(0, END)
      self.pw_entry.delete(0, END)

  def generate(self):
    # Character lists
    uppercase = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    lowercase = list("abcdefghijklmnopqrstuvwxyz")
    digits = list("0123456789")
    special = list("!@#$%^&*()-:,.<>?")

    # Ensure password has at least one of each type
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(special)
    ]

    # Add more random characters to reach desired length (e.g., 12 characters)
    length = 12
    all_characters = uppercase + lowercase + digits + special
    password += random.choices(all_characters, k=length - 4)

    # Shuffle to randomize order
    random.shuffle(password)

    # Join list into a string
    generated = ''.join(password)
    
    # Display the generated password in the entry widget
    self.pw_entry.delete(0, END)
    self.pw_entry.insert(0, generated)

    # Copy to clipboard
    self.pw_entry.clipboard_clear()
    self.pw_entry.clipboard_append(generated)

    InfoDialog(self.window, title="Password Copied!", message="Password Copied to Clipboard")

  def password_list(self):
    all_passwords = Toplevel(self.window)
    all_passwords.title("Saved passwords")
    all_passwords.config(bg="white", padx=20, pady=20)

    passwords = self.password_manager.passwords

    # Create a canvas with no border and adjust width
    canvas = Canvas(all_passwords, bg="white", bd=0, highlightthickness=0, width=530)
    scrollbar = Scrollbar(all_passwords, orient="vertical", command=canvas.yview)
    scrollable_frame = Frame(canvas, bg="white")

    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Add headers
    Label(scrollable_frame, text="Website", bg="white", font=("Verdana", 10, "bold")).grid(row=0, column=0, padx=5, pady=5, sticky="w")
    Label(scrollable_frame, text="Username", bg="white", font=("Verdana", 10, "bold")).grid(row=0, column=1, padx=5, pady=5, sticky="w")
    Label(scrollable_frame, text="Password", bg="white", font=("Verdana", 10, "bold")).grid(row=0, column=2, padx=5, pady=5, sticky="w")

    # Display passwords
    for index, entry in enumerate(passwords):
        row_color = "#FBFBFB" if index % 2 == 0 else "#F7F7F7"
        row_frame = Frame(scrollable_frame, bg=row_color)
        row_frame.grid(row=index+1, column=0, columnspan=3, padx=5, sticky="w")

        website_text = Text(row_frame, height=1, width=20, font=("Verdana", 10), wrap=WORD, bd=0, relief="flat", bg=row_color)
        website_text.grid(row=0, column=0, pady=5, sticky="w")
        website_text.insert(END, entry["Website"])
        website_text.config(state=DISABLED)

        username_text = Text(row_frame, height=1, width=20, font=("Verdana", 10), wrap=WORD, bd=0, relief="flat", bg=row_color)
        username_text.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        username_text.insert(END, entry["Username"])
        username_text.config(state=DISABLED)

        password_text = Text(row_frame, height=1, width=20, font=("Verdana", 10), wrap=WORD, bd=0, relief="flat", bg=row_color)
        password_text.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        password_text.insert(END, self.password_manager.decrypt_password(entry["Password"]))
        password_text.config(state=DISABLED)

    canvas.grid(row=0, column=0, sticky="nsew")
    scrollbar.grid(row=0, column=1, sticky="ns")

    # Set canvas height only if there are more than 9 entries
    if len(passwords) > 9:
        canvas.config(height=300)

  def search(self):
    dialog = SearchDialog(self.window)
    self.window.wait_window(dialog)  # Wait until dialog is closed
    website = dialog.result

    if website:
      result = self.password_manager.search_password(website)
      if result:
        InfoDialog(self.window, title="Search Result", message=f"{result['Website']} | {result['Username']} | {result['Password']}", width=450, height=120)
      else:
        InfoDialog(self.window, title="Not Found", message="No password found for " + website)
    else:
      InfoDialog(self.window, title="Error", message="Please Enter the Website Name")

  def delete(self):
    dialog = DeleteDialog(self.window)
    self.window.wait_window(dialog)  # Wait until dialog is closed
    website = dialog.result

    if website:
      success = self.password_manager.delete_password(website)
      if success:
        InfoDialog(self.window, title="Deleted!", message="Password for " + website + " deleted successfully.")
      else:
        InfoDialog(self.window, title="Not Found", message="No password found for " + website)
    else:
      InfoDialog(self.window, title="Error", message="Please Enter the Website Name")

PyPass()