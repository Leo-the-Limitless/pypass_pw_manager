from tkinter import *

class PyPass():
  def __init__(self):
    self.window = Tk()
    self.window.title("PyPass Password Manager")
    self.window.config(padx=20, pady=20, bg="white")

    logo_img = PhotoImage(file="logo.png")
    canvas = Canvas(self.window, width=200, height=200, bg="white", highlightthickness=0, bd=0)
    canvas.create_image(100, 100, image=logo_img)
    canvas.grid(row=0, column=1)

    #Labels
    website_lbl = Label(text="Website", bg="white")
    website_lbl.grid(row=1, column=0, pady=10, sticky="e")
    username_lbl = Label(text="Username / Email", bg="white")
    username_lbl.grid(row=2, column=0, sticky="e")
    pw_lbl = Label(text="Password", bg="white")
    pw_lbl.grid(row=3, column=0, sticky="e")

    #Entries
    website_entry = Entry(width=57, bd=1, relief="solid")
    website_entry.grid(row=1, column=1, pady=10, columnspan=2)
    username_entry = Entry(width=57, bd=1, relief="solid")
    username_entry.grid(row=2, column=1, columnspan=2)
    pw_entry = Entry(width=45, bd=1, relief="solid")
    pw_entry.grid(row=3, column=1, pady=10)

    #Buttons
    generate_btn = Button(text="Generate", bd=1, relief="solid", font=("Arial", 9, "bold"), bg="white")
    generate_btn.grid(row=3, column=2, padx=5)
    add_button = Button(text="Add", bd=1, width=48, font=("Arial", 9, "bold"), bg="#003049", fg="white", activebackground="#7CC1D7", relief="solid", pady=5)
    add_button.grid(row=4, column=1, columnspan=2, padx=2)

    see_btn = Button(text="See all passwords", bd=1, relief="solid", bg="#ffd166", font=("Arial", 9, "bold"), command=self.password_list)
    see_btn.grid(row=5, column=1, pady=10, padx=2, sticky="ew")
    search_btn = Button(text="Search", width=18, bd=1, relief="solid", font=("Arial", 9, "bold"), bg="#ffd166")
    search_btn.grid(row=5, column=0, pady=10, padx=2, sticky="ew")
    delete_btn = Button(text="Delete", bd=1, relief="solid", font=("Arial", 9, "bold"), bg="#ffd166")
    delete_btn.grid(row=5, column=2, pady=10, padx=2, sticky="ew")

    self.window.mainloop()

  def password_list(self):
    # Create a new window
    all_passwords = Toplevel(self.window)
    all_passwords.title("Saved passwords")
    all_passwords.config(bg="white")

    # Dummy data for demonstration
    passwords = [
        {"Website": "example.com", "Username": "user1@example.com", "Password": "pass123"},
        {"Website": "test.com", "Username": "testuser@test.com", "Password": "password"},
        {"Website": "mywebsite.com", "Username": "admin@mywebsite.com", "Password": "adminpass"},
    ]

    # Create header labels
    Label(all_passwords, text="Website", bg="white", font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5, pady=5)
    Label(all_passwords, text="Username", bg="white", font=("Arial", 10, "bold")).grid(row=0, column=1, padx=5, pady=5)
    Label(all_passwords, text="Password", bg="white", font=("Arial", 10, "bold")).grid(row=0, column=2, padx=5, pady=5)

    # Display each entry in the list
    for index, entry in enumerate(passwords):
        Label(all_passwords, text=entry["Website"], bg="white", font=("Arial", 9)).grid(row=index+1, column=0, padx=5, pady=5)
        Label(all_passwords, text=entry["Username"], bg="white", font=("Arial", 9)).grid(row=index+1, column=1, padx=5, pady=5)
        Label(all_passwords, text=entry["Password"], bg="white", font=("Arial", 9)).grid(row=index+1, column=2, padx=5, pady=5)

PyPass()