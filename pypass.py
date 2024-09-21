from tkinter import *

class PyPass():
  def __init__(self):
    window = Tk()
    window.title("PyPass Password Manager")
    window.config(padx=20, pady=20, bg="white")

    logo_img = PhotoImage(file="logo.png")
    canvas = Canvas(window, width=200, height=200, bg="white", border=None)
    canvas.create_image(100, 100, image=logo_img)
    canvas.grid(row=0, column=1)

    #Labels
    website_lbl = Label(text="Website", bg="white")
    website_lbl.grid(row=1, column=0, pady=10)
    username_lbl = Label(text="Username/Email", bg="white")
    username_lbl.grid(row=2, column=0)
    pw_lbl = Label(text="Password", bg="white")
    pw_lbl.grid(row=3, column=0)

    #Entries
    website_entry = Entry(width=50)
    website_entry.grid(row=1, column=1, pady=10, columnspan=2)
    username_entry = Entry(width=50)
    username_entry.grid(row=2, column=1, columnspan=2)
    pw_entry = Entry(width=20)
    pw_entry.grid(row=3, column=1)

    #Buttons
    generate_btn = Button(text="Generate password")
    generate_btn.grid(row=3, column=2)
    add_button = Button(text="Add", width=50)
    add_button.grid(row=4, column=1, columnspan=2, pady=10)

    window.mainloop()

PyPass()