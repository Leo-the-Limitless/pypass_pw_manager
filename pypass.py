from tkinter import *
import pickle
import random
from cryptography.fernet import Fernet

class CustomDialog(Toplevel):
  """
  A custom modal dialog window that can display a message and buttons.
  Useful for prompting users or displaying alerts.
  """
  def __init__(self, master, title="", message="", width=300, height=150, bg="white"):
    super().__init__(master)
    self.title(title)
    self.geometry(f"{width}x{height}")
    self.configure(bg=bg)
    self.center_window(width, height)
    self.result = None
    
    # Make the dialog modal, blocking interaction with the main window
    self.transient(master)
    self.grab_set()

    self.message = Label(self, text=message, font=("Verdana", 10), bg=bg, wraplength=width - 20)
    self.message.pack(pady=10)

    self.button_frame = Frame(self, bg=bg)
    self.button_frame.pack(pady=10)

  def center_window(self, width, height):
    """
    Centers the dialog on the screen for better user visibility.
    """
    x = (self.winfo_screenwidth() // 2) - (width // 2)
    y = (self.winfo_screenheight() // 2) - (height // 2)
    self.geometry(f"{width}x{height}+{x}+{y}")

  def add_button(self, text, command, font=("Orbitron", 9, "bold"), bg="#ffd166", fg="black"):
    button = Button(self.button_frame, text=text, command=command, font=font, bg=bg, fg=fg, relief="solid", width=10)
    button.pack(side=LEFT, padx=5)

class SearchDialog(CustomDialog):
  """
  A dialog for searching a password by entering a website name.
  Inherits from CustomDialog to provide a tailored interface.
  """
  def __init__(self, master):
    super().__init__(master, title="Search Password", message="Enter the website name to search:")
    self.result = None

    self.entry = Entry(self, font=("Verdana", 10), bd=1, relief="solid")
    self.entry.pack(pady=5)
    self.entry.focus_set() # Automatically focuses the entry field for user convenience

    self.add_button("Search", self.search)
    self.add_button("Cancel", self.cancel)

  def search(self):
    self.result = self.entry.get().strip()
    self.destroy()

  def cancel(self):
    self.result = None
    self.destroy()

class InfoDialog(CustomDialog):
  """
  A dialog for displaying informational messages or detailed content.
  Inherits from CustomDialog to provide a flexible, scrollable interface for long text.
  """
  def __init__(self, master, title, message=None, content=None, width=300, height=150):
    super().__init__(master, title=title, message=message, width=width, height=height)

    if content:
      # Display content in a read-only Text widget with scrollbars for large text.
      text_area = Text(self, wrap="none", height=10, width=50, padx=10, pady=10, bd=1, relief="solid", font=("Verdana", 10, "bold"))
      text_area.insert("1.0", content)
      text_area.config(state="disabled") # Make the text area read-only 
      text_area.pack(expand=True, fill="both", padx=15, pady=5)

      # Add vertical and horizontal scrollbars for better navigation of content
      scroll_y = Scrollbar(self, orient="vertical", command=text_area.yview)
      scroll_x = Scrollbar(self, orient="horizontal", command=text_area.xview)
      text_area.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

      scroll_y.pack(side="right", fill="y")
      scroll_x.pack(side="bottom", fill="x")

    # "OK" button to close the dialog
    ok_button = Button(
      self, text="OK", command=self.ok,
      font=("Orbitron", 9, "bold"), bg="#ffd166", fg="black",
      relief="solid", width=10
    )
    ok_button.pack(pady=(10, 20))

  def ok(self):
    """
    Closes the dialog when the "OK" button is clicked.
    """
    self.destroy()

class DeleteDialog(CustomDialog):
  """
  A dialog for deleting a password by entering the website name.
  Inherits from CustomDialog to provide a simple interface for user input.
  """
  def __init__(self, master):
    super().__init__(master, title="Delete Password", message="Enter the website name to delete:")
    self.result = None

    self.entry = Entry(self, font=("Verdana", 10), bd=1, relief="solid")
    self.entry.pack(pady=5)
    self.entry.focus_set() # Automatically focuses the entry field for user convenience

    self.add_button("Delete", self.delete)
    self.add_button("Cancel", self.cancel)

  def delete(self):
    self.result = self.entry.get().strip()
    self.destroy()

  def cancel(self):
    self.result = None
    self.destroy()

class ConfirmationDialog(CustomDialog):
  """
  A dialog to confirm action when a duplicate website entry is detected.
  Allows the user to choose between overwriting, adding a new entry, or canceling.
  """
  def __init__(self, master, website):
    super().__init__(master, title="Duplicate Website", message=f"An entry for '{website}' already exists.", width=350, height=120)
    self.result = None

    # Add action buttons for the user's decision
    self.add_button("Overwrite", self.overwrite)
    self.add_button("Add New", self.add_new)
    self.add_button("Cancel", self.cancel)

  def overwrite(self):
    self.result = "overwrite"
    self.destroy()

  def add_new(self):
    self.result = "add_new"
    self.destroy()

  def cancel(self):
    self.result = None
    self.destroy()

class MasterPINDialog(CustomDialog):
  """
  A dialog for entering a master PIN.
  Ensures the user inputs a valid 4-digit PIN or cancels the operation.
  """
  def __init__(self, master):
    super().__init__(master, title="Enter Master PIN", message="Please enter your master PIN:", width=300, height=150)
    self.result = None
    self.resizable(False, False)

    # Input field for the master PIN, masked for security
    self.pin_entry = Entry(self, show="*", font=("Verdana", 10), bd=1, relief="solid")
    self.pin_entry.pack(pady=5)
    self.pin_entry.focus_set()

    self.add_button("Login", self.verify_pin)
    self.add_button("Cancel", self.cancel)

  def verify_pin(self):
    """
    Validates the entered PIN. If valid, stores it in `result` and closes the dialog.
    Otherwise, displays an error dialog to inform the user of the input requirements.
    """
    pin = self.pin_entry.get().strip()
    if len(pin) == 4 and pin.isdigit():
      self.result = pin
      self.destroy()
    else:
      error_dialog = CustomDialog(self, title="Error", message="PIN must be 4 digits.", width=300, height=150)
      error_dialog.add_button("OK", error_dialog.destroy)

  def cancel(self):
    self.result = None
    self.destroy()

class SetPINDialog(CustomDialog):
  """
  A dialog for setting a new master PIN.
  Ensures the user creates a valid 4-digit PIN and double confirms it for accuracy.
  """
  def __init__(self, master):
    super().__init__(master, title="Set Master PIN", message="Create a master PIN for security:", width=300, height=150)
    self.result = None

    # Input field for entering the new PIN, masked for security
    self.pin_entry = Entry(self, show="*", font=("Verdana", 10), bd=1, relief="solid")
    self.pin_entry.pack(pady=5)
    self.pin_entry.focus_set() 

    self.add_button("Set PIN", self.set_pin)
    self.add_button("Cancel", self.cancel)

  def set_pin(self):
    """
    Validates the entered PIN. If valid, prompts the user to confirm the PIN.
    If invalid, displays an error dialog.
    """
    pin = self.pin_entry.get().strip()

    if len(pin) == 4 and pin.isdigit():  # Ensure PIN is 4 digits and numeric
      # Ask for confirmation of the PIN
      self.show_pin_confirmation(pin)
    else:
      # Show error dialog if PIN is not 4 digits
      error_dialog = CustomDialog(self, title="Error", message="PIN must be 4 digits.", width=300, height=150)
      error_dialog.add_button("OK", error_dialog.destroy)

  def show_pin_confirmation(self, original_pin):
    """
    Opens a confirmation dialog to re-enter and confirm the master PIN.
    Ensures that the user accurately remembers the PIN they set.
    """
    # Create a new dialog to confirm the PIN
    confirm_dialog = CustomDialog(self, title="Confirm PIN", message="Re-enter your master PIN to confirm:", width=300, height=150)

    confirm_pin_entry = Entry(confirm_dialog, show="*", font=("Verdana", 10), bd=1, relief="solid")
    confirm_pin_entry.pack(pady=5)
    confirm_pin_entry.focus_set()

    confirm_dialog.add_button("Confirm", lambda: self.confirm_pin(confirm_dialog, confirm_pin_entry, original_pin))
    confirm_dialog.add_button("Cancel", confirm_dialog.destroy)

  def confirm_pin(self, dialog, confirm_pin_entry, original_pin):
    """
    Compares the re-entered PIN with the original PIN.
    Saves the PIN if they match, otherwise displays an error dialog.
    """
    confirm_pin = confirm_pin_entry.get().strip()

    if confirm_pin == original_pin:
      self.result = original_pin
      dialog.destroy()
      self.destroy()
    else:
      error_dialog = CustomDialog(self, title="Error", message="PINs do not match. Please try again.", width=300, height=150)
      error_dialog.add_button("OK", error_dialog.destroy)

  def cancel(self):
    self.result = None
    self.destroy()

class PasswordManager(object):
  """
  Manages passwords using encryption and stores them securely.
  Handles adding, searching, updating, and deleting passwords, as well as PIN management.
  """
  def __init__(self, master, filename="passwords.pkl", key_file="secret.key", pin_file="master_pin.pkl"):
        self.master = master
        self.filename = filename  # File for storing encrypted passwords
        self.key_file = key_file  # File for storing the encryption key
        self.pin_file = pin_file  # File for storing the encrypted master PIN
        self.key = self.load_key()  # Load or generate encryption key
        self.cipher = Fernet(self.key)  # Initialize encryption handler
        self.passwords = self.load_passwords()  # Load existing passwords

  def load_key(self):
      """
      Loads the encryption key. Generates and saves a new key if none exists.
      """
      try:
          with open(self.key_file, "rb") as key_file:
              return key_file.read()
      except FileNotFoundError:
          key = Fernet.generate_key()
          with open(self.key_file, "wb") as key_file:
              key_file.write(key)
          return key

  def load_master_pin(self):
      """
      Loads and decrypts the master PIN from storage.
      Returns None if no PIN is found.
      """
      try:
          with open(self.pin_file, "rb") as file:
              encrypted_pin = pickle.load(file)
              return self.cipher.decrypt(encrypted_pin).decode()
      except FileNotFoundError:
          return None

  def save_master_pin(self, pin):
      """
      Encrypts and saves the master PIN securely to storage.
      """
      encrypted_pin = self.cipher.encrypt(pin.encode())
      with open(self.pin_file, "wb") as file:
          pickle.dump(encrypted_pin, file)

  def change_master_pin(self, new_pin):
      """
      Changes the master PIN and shows a success message.
      """
      self.save_master_pin(new_pin)
      dialog = CustomDialog(self.master, title="Success", message="Master PIN changed successfully.", width=300, height=150)
      dialog.add_button("OK", dialog.destroy)

  def encrypt_password(self, password):
    return self.cipher.encrypt(password.encode()).decode()

  def decrypt_password(self, encrypted_password):
    return self.cipher.decrypt(encrypted_password.encode()).decode()

  def add_password(self, website, username, password):
    """
    Adds a new password entry. Handles duplicate websites by prompting the user
    to overwrite, add a new entry, or cancel the operation.
    """
    # Check for an existing entry with the same website name
    existing_entry = None
    for entry in self.passwords:
        if entry["Website"].lower() == website.lower():
            existing_entry = entry
            break

    if existing_entry:
        dialog = ConfirmationDialog(self.master, website)
        self.master.wait_window(dialog)  # Wait for user response

        if dialog.result == "overwrite":
            self.passwords.remove(existing_entry)  # Remove the existing entry
        elif dialog.result == "add_new":
            pass  # Proceed to add new entry
        else:
            return  # Cancelled by user, do nothing

    # Encrypt the password and add to the list
    encrypted_password = self.encrypt_password(password)
    self.passwords.append({"Website": website, "Username": username, "Password": encrypted_password})
    self.save_passwords()

    # Show confirmation message
    InfoDialog(self.master, title="Password Added!", message=f"Password for {website} added successfully.")
    
  def search_password(self, website):
    """
    Searches for passwords by website. Decrypts passwords for display.
    Returns a list of matching entries or None if no matches are found.
    """
    results = []
    for pw in self.passwords:
      if pw["Website"].lower() == website.lower():
        pw_copy = pw.copy()
        pw_copy["Password"] = self.decrypt_password(pw["Password"])
        results.append(pw_copy)

    return results if results else None

  def delete_password(self, website):
    """
    Deletes a password entry by website name. Returns True if an entry was deleted, False otherwise.
    If multiple entries exist for the website, asks user to confirm whether to delete all or just one entry.
    """
    # Find all entries with the matching website (case-insensitive)
    matching_entries = [pw for pw in self.passwords if pw["Website"].lower() == website.lower()]
    
    if len(matching_entries) > 1:
      # Ask for confirmation to delete all or just one entry
      delete_dialog = CustomDialog(
        self.master,  
        title="Confirm Deletion",
        message=f"There are {len(matching_entries)} entries for {website}. Delete all or just the first one?",
        width=300,  
        height=150 
      )

      delete_dialog.add_button("Delete All", lambda: self.set_delete_result(delete_dialog, "Delete All"))
      delete_dialog.add_button("Delete One", lambda: self.set_delete_result(delete_dialog, "Delete One"))
      
      self.master.wait_window(delete_dialog)  # Wait for dialog to close
      
      # Perform deletion based on user's choice
      if delete_dialog.result == "Delete All":
        self.delete_all_entries(website)
        return True
      elif delete_dialog.result == "Delete One":
        self.delete_one_entry(website)
        return True
      else:
        return
    
    elif len(matching_entries) == 1:
      # Only one entry exists, delete it
      self.passwords = [pw for pw in self.passwords if pw["Website"].lower() != website.lower()]
      self.save_passwords()
      return True
    else:
      # No entries found for the website
      return False

  def set_delete_result(self, dialog, result):
    """
    Sets the result attribute in the dialog and closes it.
    """
    dialog.result = result
    dialog.destroy()

  def delete_all_entries(self, website):
    """Deletes all entries for the given website."""
    self.passwords = [pw for pw in self.passwords if pw["Website"].lower() != website.lower()]
    self.save_passwords()

  def delete_one_entry(self, website):
    """Deletes one entry for the given website."""
    matching_entries = [pw for pw in self.passwords if pw["Website"].lower() == website.lower()]
    if matching_entries:
      self.passwords.remove(matching_entries[0])  # Delete the first match
      self.save_passwords()

  def save_passwords(self):
    """
    Encrypts and saves the passwords list to storage.
    Shows an error dialog if saving fails.
    """
    try:
      with open(self.filename, "wb") as file:
        pickle.dump(self.passwords, file)
    except Exception as e:
      self.window = Toplevel(self.master)
      self.window.title("PyPass Password Manager")
      self.window.config(padx=20, pady=20, bg="white")
      InfoDialog(self.window, title="Error", message=f"An error occurred while saving: {e}")

  def load_passwords(self):
    """
    Loads the saved passwords from file, decrypts them, and returns the list.
    Returns an empty list if no passwords are found or if an error occurs.
    """
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
    # Set the unnecessary window's size to a minimal size to begin with, then center it on the screen
    # To hide it behind the correct toplevel that is supposed to be shown
    # This window will be returned to its normal size after a successful login
    self.window.geometry("1x1+{}+{}".format(
        self.window.winfo_screenwidth() // 2, 
        self.window.winfo_screenheight() // 2
    ))
    self.window.title("PyPass Password Manager")
    self.window.config(padx=20, pady=20, bg="white")
    self.password_manager = PasswordManager(self.window)

    master_pin = self.password_manager.load_master_pin()

    if master_pin is None:
        # No master PIN found, so prompt the user to create one
        set_pin_dialog = SetPINDialog(self.window)
        self.window.wait_window(set_pin_dialog)
        if set_pin_dialog.result:
            self.password_manager.save_master_pin(set_pin_dialog.result)
            master_pin = set_pin_dialog.result
        else:
            self.window.destroy()
            return

    # Prompt for PIN to log in
    pin_dialog = MasterPINDialog(self.window)
    self.window.wait_window(pin_dialog)

    if pin_dialog.result == master_pin:
      # If PIN matches, initialize the main application window
      window_width = 580
      window_height = 470

      # Get screen width and height
      screen_width = self.window.winfo_screenwidth()
      screen_height = self.window.winfo_screenheight()

      # Calculate the position to center the window
      position_top = (screen_height // 2) - (window_height // 2)
      position_left = (screen_width // 2) - (window_width // 2)

      # Set the geometry with the calculated position to center it
      self.window.geometry(f'{window_width}x{window_height}+{position_left}+{position_top}')
      
      self.create_ui()

    elif pin_dialog.result != None and pin_dialog.result != master_pin:
        # Show error dialog if PIN is incorrect
        error_dialog = CustomDialog(self.window, title="Error", message="Incorrect PIN", width=300, height=150)
        error_dialog.add_button("OK", self.window.destroy)
    else:
      return

    # Try loading the logo image
    try:
      logo_img = PhotoImage(file="logo.png")
      canvas = Canvas(self.window, width=200, height=200, bg="white", highlightthickness=0, bd=0)
      canvas.create_image(100, 100, image=logo_img)
      canvas.grid(row=1, column=1)
    except Exception as e:
      print(f"Error loading image: {e}")

    # Labels for fields
    website_lbl = Label(text="Website", bg="white", font=("Verdana", 9, "bold"))
    website_lbl.grid(row=2, column=0, pady=10, sticky="e")
    username_lbl = Label(text="Username / Email", bg="white", font=("Verdana", 9, "bold"))
    username_lbl.grid(row=3, column=0, sticky="e")
    pw_lbl = Label(text="Password", bg="white", font=("Verdana", 9, "bold"))
    pw_lbl.grid(row=4, column=0, sticky="e")

    # Entry fields for website, username, and password
    self.website_entry = Entry(width=43, bd=1, relief="solid", font=("Verdana", 10, "bold"))
    self.website_entry.grid(row=2, column=1, pady=10, columnspan=2, ipady=3)
    self.username_entry = Entry(width=43, bd=1, relief="solid", font=("Verdana", 10, "bold"))
    self.username_entry.grid(row=3, column=1, columnspan=2, ipady=3)
    self.pw_entry = Entry(width=33, bd=1, relief="solid", font=("Verdana", 10, "bold"))
    self.pw_entry.grid(row=4, column=1, pady=10, ipady=3, padx=5)

    # Buttons for various actions
    generate_btn = Button(text=" Generate ", bd=1, relief="solid", font=("Orbitron", 9, "bold"), bg="white", command=self.generate)
    generate_btn.grid(row=4, column=2, padx=5)
    add_button = Button(text="Add", bd=1, width=43, font=("Orbitron", 9, "bold"), bg="#003049", fg="white", activebackground="#00263A", activeforeground="white", relief="solid", pady=5, command=self.add)
    add_button.grid(row=5, column=1, columnspan=2, padx=2)

    see_btn = Button(text="See all passwords", bd=1, relief="solid", bg="#ffd166", activebackground="#E6B854", font=("Orbitron", 9, "bold"), command=self.password_list)
    see_btn.grid(row=6, column=1, pady=10, padx=2, sticky="ew")
    search_btn = Button(text="Search", width=14, bd=1, relief="solid", font=("Orbitron", 9, "bold"), bg="#ffd166", activebackground="#E6B854", command=self.search)
    search_btn.grid(row=6, column=0, pady=10, padx=2, sticky="ew")
    delete_btn = Button(text="Delete", bd=1, relief="solid", font=("Orbitron", 9, "bold"), bg="#ffd166", activebackground="#E6B854", command=self.delete)
    delete_btn.grid(row=6, column=2, pady=10, padx=2, sticky="ew")

    self.window.mainloop()

  def create_ui(self):
    """Sets up the UI for the Change PIN button."""
    change_pin_btn = Button(self.window, text="Change PIN", bd=1, font=("Orbitron", 9, "bold"), bg="#003049", fg="white", activebackground="#00263A", activeforeground="white", relief="solid", pady=5, command=self.change_pin)
    change_pin_btn.grid(row=0, column=2)

  def change_pin(self):
    """Allows the user to change the master PIN."""
    set_pin_dialog = SetPINDialog(self.window)
    self.window.wait_window(set_pin_dialog)
    if set_pin_dialog.result:
        self.password_manager.change_master_pin(set_pin_dialog.result)

  def add(self):
    """Adds a new password entry after validating user input."""
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
    """Generates a secure password and copies it to the clipboard."""
    # Character lists
    uppercase = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    lowercase = list("abcdefghijklmnopqrstuvwxyz")
    digits = list("0123456789")
    special = list("!@#$%^&*.?")

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
    """Displays all saved passwords in a scrollable window."""
    all_passwords = Toplevel(self.window)
    all_passwords.title("Saved passwords")
    all_passwords.config(bg="white", padx=20, pady=20)
    all_passwords.grab_set()

    passwords = self.password_manager.passwords

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
        row_color = "#FEF8C6" if index % 2 == 0 else "#FFFFEB"
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

    """
    When there are more than 9 entries, the canvas is given a fixed height of 300 pixels
    to ensure the scrollable area is appropriately sized.
    If there are fewer than 9, the canvas height is determined dynamically based on the number of entries, 
    so it adjusts automatically to fit all of them without scrolling too much.
    """
    if len(passwords) > 9:
        canvas.config(height=300)

  def search(self):
    """Searches for passwords by website name."""
    dialog = SearchDialog(self.window)
    self.window.wait_window(dialog) 
    website = dialog.result

    if website:
      result = self.password_manager.search_password(website)
      if result:
        # Header for the results page UI
        results_text = "Website | Username | Password\n"
        # Add a divider between header and results
        results_text += "-" * 40 + "\n"
        for r in result:
          results_text += f"{r['Website']} | {r['Username']} | {r['Password']}\n"

        # Display all the results in a single dialog
        InfoDialog(
            self.window,
            title="Search Results",
            message=None,  
            width=500,
            height=400,
            content=results_text  # Pass results text to the dialog
        )
      else:
        InfoDialog(
            self.window,
            title="Not Found",
            message=f"No password found for {website}"
        )
    elif website == "":
      InfoDialog(
        self.window,
        title="Error",
        message="Please Enter the Website Name"
      )

  def delete(self):
    """Deletes a password entry."""
    dialog = DeleteDialog(self.window)
    self.window.wait_window(dialog)  # Wait until dialog is closed
    website = dialog.result

    if website:
      success = self.password_manager.delete_password(website)
      if success:
        InfoDialog(self.window, title="Deleted!", message="Password for " + website + " deleted successfully.")
      elif success == False:
        InfoDialog(self.window, title="Not Found", message="No password found for " + website)
    elif website == "":
      InfoDialog(self.window, title="Error", message="Please Enter the Website Name")

PyPass()