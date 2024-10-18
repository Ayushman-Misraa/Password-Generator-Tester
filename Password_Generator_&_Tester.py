import tkinter as tk
import hashlib
import requests
import re
import random
import string
from tkinter import messagebox

def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Weak: Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Weak: Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return "Weak: Password must include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Weak: Password must include at least one special character."
    
    return "Strong: Password meets all requirements."

def check_password_leak(entry_password, result):
    password = entry_password.get()
    sha1_password = hashlib.sha1(password.encode()).hexdigest().upper()
    first5_hash = sha1_password[:5]
    tail_hash = sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{first5_hash}"
    response = requests.get(url)

    if response.status_code == 200:
        hashes = response.text.splitlines()
        for h in hashes:
            h_prefix, count = h.split(':')
            if tail_hash == h_prefix:
                result.set(f"Password has been leaked {count} times!")
                return
        result.set("Password is safe and not found in breaches.")
    else:
        result.set("Error checking password. Please try again.")

def toggle_password_visibility(entry_password, show_password_var):
    if show_password_var.get():
        entry_password.config(show="")
    else:
        entry_password.config(show="*")

def open_password_checker():
    password_checker_window = tk.Toplevel(root)
    password_checker_window.title("Password Leak Checker")
    password_checker_window.geometry("400x400")
    password_checker_window.config(bg="#152238")

    label_password = tk.Label(password_checker_window, text="Enter your password:", bg="#152238", fg="white", font=("Arial", 12))
    label_password.pack(pady=(20, 5))

    entry_password = tk.Entry(password_checker_window, show="*", width=30, font=("Arial", 12))
    entry_password.pack(pady=(0, 15))

    show_password_var = tk.BooleanVar()
    checkbox_show_password = tk.Checkbutton(password_checker_window, text="Show Password", variable=show_password_var,
                                             command=lambda: toggle_password_visibility(entry_password, show_password_var),
                                             bg="#152238", fg="white")
    checkbox_show_password.pack(pady=(0, 15))

    result = tk.StringVar()
    label_result = tk.Label(password_checker_window, textvariable=result, bg="#152238", fg="red", font=("Arial", 12), wraplength=350)
    label_result.pack(pady=(10, 20))

    btn_check_strength = tk.Button(password_checker_window, text="Check Password Strength",
                                    command=lambda: result.set(check_password_strength(entry_password.get())),
                                    width=20, bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                                    highlightbackground="#32CD32", font=("Arial", 12))
    btn_check_strength.pack(pady=(0, 10))

    btn_check_leak = tk.Button(password_checker_window, text="Check Leaked Status",
                                command=lambda: check_password_leak(entry_password, result),
                                width=20, bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                                highlightbackground="#32CD32", font=("Arial", 12))
    btn_check_leak.pack(pady=(0, 15))

    btn_close = tk.Button(password_checker_window, text="Close", command=password_checker_window.destroy,
                          width=20, bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                          highlightbackground="#32CD32", font=("Arial", 12))
    btn_close.pack(pady=(0, 15))

def copy_password():
    root.clipboard_clear()
    root.clipboard_append(password_entry.get())
    messagebox.showinfo("Copied", "Password copied to clipboard!")

def generate_password(length_entry, uppercase_var, numbers_var, symbols_var):
    try:
        length = int(length_entry.get())
    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter a valid number for the length.")
        return

    if length < 1:
        messagebox.showerror("Invalid Length", "Password length should be at least 1.")
        return
    
    include_uppercase = uppercase_var.get()
    include_numbers = numbers_var.get()
    include_symbols = symbols_var.get()

    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase if include_uppercase else ''
    digits = string.digits if include_numbers else ''
    symbols = string.punctuation if include_symbols else ''
    
    all_characters = lowercase_letters + uppercase_letters + digits + symbols
    
    if not all_characters:
        messagebox.showerror("No Characters Selected", "Please select at least one character type.")
        return
    
    password = []

    if include_uppercase:
        password.append(random.choice(uppercase_letters))
    if include_numbers:
        password.append(random.choice(digits))
    if include_symbols:
        password.append(random.choice(symbols))
    
    password += random.choices(all_characters, k=length - len(password))
    random.shuffle(password)

    generated_password = ''.join(password)
    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated_password)

def open_password_generator():
    generator_window = tk.Toplevel(root)
    generator_window.title("Password Generator")
    generator_window.geometry("400x400")
    generator_window.config(bg="#152238")

    tk.Label(generator_window, text="Password Length:", bg="#152238", fg="white", font=('Arial', 12)).grid(row=0, column=0, padx=15, pady=15)
    length_entry = tk.Entry(generator_window, font=('Arial', 12))
    length_entry.grid(row=0, column=1, padx=15, pady=15)
    length_entry.insert(0, "12")

    uppercase_var = tk.BooleanVar(value=True)
    uppercase_check = tk.Checkbutton(generator_window, text="Include Uppercase", variable=uppercase_var,
                                      bg="#152238", fg="white", selectcolor="#152238")
    uppercase_check.grid(row=1, column=0, columnspan=2, padx=15, pady=5)

    numbers_var = tk.BooleanVar(value=True)
    numbers_check = tk.Checkbutton(generator_window, text="Include Numbers", variable=numbers_var,
                                    bg="#152238", fg="white", selectcolor="#152238")
    numbers_check.grid(row=2, column=0, columnspan=2, padx=15, pady=5)

    symbols_var = tk.BooleanVar(value=True)
    symbols_check = tk.Checkbutton(generator_window, text="Include Symbols", variable=symbols_var,
                                    bg="#152238", fg="white", selectcolor="#152238")
    symbols_check.grid(row=3, column=0, columnspan=2, padx=15, pady=5)

    generate_button = tk.Button(generator_window, text="Generate Password", 
                                 command=lambda: generate_password(length_entry, uppercase_var, numbers_var, symbols_var),
                                 bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                                 highlightbackground="#32CD32", font=("Arial", 12))
    generate_button.grid(row=4, column=0, columnspan=2, pady=15)

    global password_entry  # Declare password_entry as a global variable
    password_entry = tk.Entry(generator_window, width=40, font=('Arial', 12))
    password_entry.grid(row=5, column=0, columnspan=2, padx=15, pady=15)

    copy_button = tk.Button(generator_window, text="Copy to Clipboard", command=copy_password,
                            bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                            highlightbackground="#32CD32", font=("Arial", 12))
    copy_button.grid(row=6, column=0, columnspan=2, pady=15)

def quit_application():
    root.quit()

root = tk.Tk()
root.title("Password Utility")
root.geometry("400x300")
root.config(bg="#152238")

btn_checker = tk.Button(root, text="Open Password Leak Checker", command=open_password_checker,
                        bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                        highlightbackground="#32CD32", font=("Arial", 12))
btn_checker.pack(pady=15)

btn_generator = tk.Button(root, text="Open Password Generator", command=open_password_generator,
                           bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                           highlightbackground="#32CD32", font=("Arial", 12))
btn_generator.pack(pady=15)

btn_quit = tk.Button(root, text="Quit", command=quit_application,
                     bg="#152238", fg="#32CD32", borderwidth=2, relief="solid",
                     highlightbackground="#32CD32", font=("Arial", 12))
btn_quit.pack(pady=15)

root.mainloop()
