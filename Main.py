import tkinter as tk
from tkinter import messagebox
import sqlite3
import qrcode
import os
import csv
from hashlib import sha256

# Basic Blockchain implementation
class Block:
    def _init_(self, index, previous_hash, data, nonce=0):
        self.index = index
        self.previous_hash = previous_hash
        self.data = data
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = str(self.index) + self.previous_hash + str(self.data) + str(self.nonce)
        return sha256(block_data.encode()).hexdigest()

class Blockchain:
    def _init_(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "0", "Genesis Block")

    def get_latest_block(self):
        return self.chain[-1]

    def add_block(self, new_data):
        latest_block = self.get_latest_block()
        new_block = Block(len(self.chain), latest_block.hash, new_data)
        self.chain.append(new_block)

# Initialize Blockchain
blockchain = Blockchain()

import tkinter as tk
from tkinter import messagebox
import sqlite3

db_file = "users.db"

# Database Setup
def setup_db():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL,
                        role TEXT NOT NULL)''')
    conn.commit()
    conn.close()

setup_db()

# Admin Page with User Creation Form
class AdminPage:
    def _init_(self, root):
        self.root = root
        self.root.title("Admin Page")
        self.root.geometry("400x400")

        # Section for adding user accounts
        tk.Label(root, text="Create User Account", font=("Arial", 16)).pack(pady=20)
        
        # User Creation Inputs
        tk.Label(root, text="New Username").pack(pady=5)
        self.new_user = tk.Entry(root)
        self.new_user.pack(pady=5)

        tk.Label(root, text="New Password").pack(pady=5)
        self.new_password = tk.Entry(root, show="*")
        self.new_password.pack(pady=5)

        self.role_var = tk.StringVar()
        self.role_var.set("user")  # Default role is user

        tk.Label(root, text="Select Role").pack(pady=5)
        tk.Radiobutton(root, text="User", variable=self.role_var, value="user").pack(pady=2)
        tk.Radiobutton(root, text="Admin", variable=self.role_var, value="admin").pack(pady=2)

        tk.Button(root, text="Create User", command=self.create_user).pack(pady=10)

    # Function to create a new user
    def create_user(self):
        username = self.new_user.get()
        password = self.new_password.get()
        role = self.role_var.get()

        if username and password:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                           (username, password, role))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", f"User '{username}' created with role '{role}'")
        else:
            messagebox.showerror("Error", "Please enter a valid username and password")

# Root Window Setup
if _name_ == "_main_":
    root = tk.Tk()
    admin_page = AdminPage(root)
    root.mainloop()

# Add some default admin
def insert_default_admin():
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", ("admin", "admin123", "admin"))
    conn.commit()
    conn.close()

setup_db()
insert_default_admin()

# QR Code Generation
def generate_qr_code(product_id):
    img = qrcode.make(product_id)
    img.save(f"{product_id}.png")
    messagebox.showinfo("QR Code", f"QR Code for {product_id} generated!")

# CSV Setup
csv_file = 'transport_data.csv'
if not os.path.exists(csv_file):
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Product ID", "Location", "Weight", "Humidity", "Methane"])

# GUI for Login
class LoginPage:
    def _init_(self, root):
        self.root = root
        self.root.title("Food Monitoring System - Login")
        self.root.geometry("400x400")
        
        # Admin Login
        tk.Label(root, text="Admin Login", font=("Arial", 16)).pack(pady=10)
        self.admin_user = tk.Entry(root)
        self.admin_pass = tk.Entry(root, show="*")
        self.admin_user.pack(pady=5)
        self.admin_pass.pack(pady=5)
        tk.Button(root, text="Admin Login", command=self.admin_login).pack(pady=10)

        # User Login
        tk.Label(root, text="User Login", font=("Arial", 16)).pack(pady=10)
        self.user_user = tk.Entry(root)
        self.user_pass = tk.Entry(root, show="*")
        self.user_user.pack(pady=5)
        self.user_pass.pack(pady=5)
        tk.Button(root, text="User Login", command=self.user_login).pack(pady=10)

    def admin_login(self):
        username = self.admin_user.get()
        password = self.admin_pass.get()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=? AND role='admin'", (username, password))
        result = cursor.fetchone()
        conn.close()
        if result:
            AdminPage(tk.Toplevel(self.root))
        else:
            messagebox.showerror("Error", "Invalid admin credentials")
    
    def user_login(self):
        username = self.user_user.get()
        password = self.user_pass.get()
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=? AND role='user'", (username, password))
        result = cursor.fetchone()
        conn.close()
        if result:
            UserPage(tk.Toplevel(self.root))
        else:
            messagebox.showerror("Error", "Invalid user credentials")

    # Function to create a new user account
def create_user(self):
    username = self.new_user.get()
    password = self.new_password.get()
    role = self.role_var.get()  # Either 'admin' or 'user'

    if username and password:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                       (username, password, role))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", f"User '{username}' created with role '{role}'")
    else:
        messagebox.showerror("Error", "Please enter a valid username and password")


# Admin Page with Product Entry and User Creation
class AdminPage:
    def _init_(self, root):
        self.root = root
        self.root.title("Admin Page")
        self.root.geometry("400x600")

        # Section for adding product data
        tk.Label(root, text="Enter Product Details", font=("Arial", 16)).pack(pady=10)

        # Farmer Name
        tk.Label(root, text="Farmer Name").pack(pady=5)
        self.farmer_name = tk.Entry(root)
        self.farmer_name.pack(pady=5)

        # Village
        tk.Label(root, text="Village").pack(pady=5)
        self.village = tk.Entry(root)
        self.village.pack(pady=5)

        # Temperature
        tk.Label(root, text="Temperature").pack(pady=5)
        self.temperature = tk.Entry(root)
        self.temperature.pack(pady=5)

        # Weight
        tk.Label(root, text="Weight (kg)").pack(pady=5)
        self.weight = tk.Entry(root)
        self.weight.pack(pady=5)

        # Methane Level
        tk.Label(root, text="Methane Level (ppm)").pack(pady=5)
        self.methane = tk.Entry(root)
        self.methane.pack(pady=5)

        # Humidity
        tk.Label(root, text="Humidity (%)").pack(pady=5)
        self.humidity = tk.Entry(root)
        self.humidity.pack(pady=5)

        # Add Product Button
        tk.Button(root, text="Add Product", command=self.add_product).pack(pady=10)

        # Section for adding user accounts
        tk.Label(root, text="Create User Account", font=("Arial", 16)).pack(pady=20)
        
        # User Creation Inputs
        tk.Label(root, text="New Username").pack(pady=5)
        self.new_user = tk.Entry(root)
        self.new_user.pack(pady=5)

        tk.Label(root, text="New Password").pack(pady=5)
        self.new_password = tk.Entry(root, show="*")
        self.new_password.pack(pady=5)

        self.role_var = tk.StringVar()
        self.role_var.set("user")  # Default role is user

        tk.Label(root, text="Select Role").pack(pady=5)
        tk.Radiobutton(root, text="User", variable=self.role_var, value="user").pack(pady=2)
        tk.Radiobutton(root, text="Admin", variable=self.role_var, value="admin").pack(pady=2)

        tk.Button(root, text="Create User", command=self.create_user).pack(pady=10)

    # Function to add product
    def add_product(self):
        farmer_name = self.farmer_name.get()
        village = self.village.get()
        temperature = self.temperature.get()
        weight = self.weight.get()
        methane = self.methane.get()
        humidity = self.humidity.get()

        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO products (farmer_name, village, temperature, weight, methane, humidity)
                          VALUES (?, ?, ?, ?, ?, ?)''', (farmer_name, village, temperature, weight, methane, humidity))
        conn.commit()
        conn.close()
        messagebox.showinfo("Success", "Product added successfully")

    # Function to create user
    def create_user(self):
        username = self.new_user.get()
        password = self.new_password.get()
        role = self.role_var.get()

        if username and password:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                           (username, password, role))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", f"User '{username}' created as '{role}'")
        else:
            messagebox.showerror("Error", "Please enter a valid username and password")

# User Page
class UserPage:
    def _init_(self, root):
        self.root = root
        self.root.title("User Page")
        self.root.geometry("400x400")

        tk.Label(root, text="Scan QR Code to Access Product Info", font=("Arial", 16)).pack(pady=20)
        tk.Button(root, text="Scan QR Code", command=self.scan_qr).pack(pady=20)

    def scan_qr(self):
        # Here, you'd implement QR scanning logic
        # For simplicity, we simulate the scanning by accessing the database directly
        product_id = 'example_product_id'  # Simulate scanning
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products WHERE farmer_name=?", (product_id,))
        product = cursor.fetchone()
        conn.close()

        if product:
            messagebox.showinfo("Product Info", 
                                f"Farmer: {product[1]}\n"
                                f"Village: {product[2]}\n"
                                f"Temperature: {product[3]} °C\n"
                                f"Weight: {product[4]} kg\n"
                                f"Methane: {product[5]} ppm\n"
                                f"Humidity: {product[6]} %")
        else:
            messagebox.showerror("Error", "Product not found")

if _name_ == "_main_":
    root = tk.Tk()
    login_page = LoginPage(root)
    root.mainloop()
