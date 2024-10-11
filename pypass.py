from tkinter import *
from tkinter import simpledialog
from tkinter import messagebox
import pickle

class PasswordManager:
  def __init__(self, filename="passwords.pkl"):
    self.filename = filename
    self.passwords = self.load_passwords()

  def add_password(self, website, username, password):
    self.passwords.append({"Website": website, "Username": username, "Password": password})
    self.save_passwords()
    messagebox.showinfo("Added!", f"Password for {website} added successfully.")

  def search_password(self, website):
    for pw in self.passwords:
      if pw["Website"] == website:
        return pw
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
      messagebox.showerror("Error", f"An error occurred while saving: {e}")

  def load_passwords(self):
    # Loads passwords using pickle, or returns an empty list if file not found.
    try:
      with open(self.filename, "rb") as file:
        return pickle.load(file)
    except FileNotFoundError:
      return []
    except Exception as e:
      messagebox.showerror("Error", f"An error occurred while loading passwords: {e}")
      return []

class PyPass():
  def __init__(self):
    self.password_manager = PasswordManager()
    self.window = Tk()
    self.window.title("PyPass Password Manager")
    self.window.config(padx=20, pady=20, bg="white")

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
      messagebox.showerror("Error", "Please Fill in All Fields.")
    else:
      self.password_manager.add_password(website, username, password)
      self.website_entry.delete(0, END)
      self.username_entry.delete(0, END)
      self.pw_entry.delete(0, END)

  def generate(self):
    # Simple generation logic
    generated = "kl%3l2kda?12"
    self.pw_entry.delete(0, END)
    self.pw_entry.insert(0, generated)
    messagebox.showinfo("Copied!", "Password Copied to Clipboard")

  def password_list(self):
    all_passwords = Toplevel(self.window)
    all_passwords.title("Saved passwords")
    all_passwords.config(bg="white")

    passwords = self.password_manager.passwords

    Label(all_passwords, text="Website", bg="white", font=("Verdana", 10, "bold")).grid(row=0, column=0, padx=5, pady=5, sticky="w")
    Label(all_passwords, text="Username", bg="white", font=("Verdana", 10, "bold")).grid(row=0, column=1, padx=5, pady=5, sticky="w")
    Label(all_passwords, text="Password", bg="white", font=("Verdana", 10, "bold")).grid(row=0, column=2, padx=5, pady=5, sticky="w")

    for index, entry in enumerate(passwords):
      Label(all_passwords, text=entry["Website"], bg="white", font=("Verdana", 9)).grid(row=index+1, column=0, padx=5, pady=5, sticky="w")
      Label(all_passwords, text=entry["Username"], bg="white", font=("Verdana", 9)).grid(row=index+1, column=1, padx=5, pady=5, sticky="w")
      Label(all_passwords, text=entry["Password"], bg="white", font=("Verdana", 9)).grid(row=index+1, column=2, padx=5, pady=5, sticky="w")

  def search(self):
    search = simpledialog.askstring("Search", "Enter the website name to search...")
    if search:
      result = self.password_manager.search_password(search)
      if result:
        messagebox.showinfo("Search Result", f"{result['Website']} | {result['Username']} | {result['Password']}")
      else:
        messagebox.showerror("Not Found", "No password found for " + search)
    else:
      messagebox.showerror("Error", "Please Enter the Website Name")

  def delete(self):
    delete = simpledialog.askstring("Delete", "Enter the website name to delete...")
    if delete:
      success = self.password_manager.delete_password(delete)
      if success:
        messagebox.showinfo("Deleted!", "Password for " + delete + " Deleted Successfully.")
      else:
        messagebox.showerror("Not Found", "No password found for " + delete)
    else:
      messagebox.showerror("Error", "Please Enter the Website Name")

PyPass()