# gui_interface.py
import tkinter as tk
from tkinter import ttk, messagebox
import pyperclip

class PasswordGeneratorGUI:
    def __init__(self, root, password_generator, two_fa, strength_evaluator):
        self.root = root
        self.password_generator = password_generator
        self.two_fa = two_fa
        self.strength_evaluator = strength_evaluator
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the main GUI interface"""
        self.root.title("Secure Password Generator with 2FA")
        self.root.geometry("600x500")
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Password Generation Section
        gen_frame = ttk.LabelFrame(main_frame, text="Password Generation", padding="10")
        gen_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Length selection
        ttk.Label(gen_frame, text="Length:").grid(row=0, column=0, sticky=tk.W)
        self.length_var = tk.IntVar(value=16)
        length_spin = ttk.Spinbox(gen_frame, from_=8, to=32, textvariable=self.length_var, width=5)
        length_spin.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Character options
        self.upper_var = tk.BooleanVar(value=True)
        self.lower_var = tk.BooleanVar(value=True)
        self.digit_var = tk.BooleanVar(value=True)
        self.symbol_var = tk.BooleanVar(value=True)
        self.ambiguous_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(gen_frame, text="Uppercase (A-Z)", variable=self.upper_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(gen_frame, text="Lowercase (a-z)", variable=self.lower_var).grid(row=1, column=1, sticky=tk.W)
        ttk.Checkbutton(gen_frame, text="Digits (0-9)", variable=self.digit_var).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(gen_frame, text="Symbols (!@#%)", variable=self.symbol_var).grid(row=2, column=1, sticky=tk.W)
        ttk.Checkbutton(gen_frame, text="Exclude ambiguous characters", variable=self.ambiguous_var).grid(row=3, column=0, columnspan=2, sticky=tk.W)
        
        # Generate button
        ttk.Button(gen_frame, text="Generate Password", command=self.generate_password).grid(row=4, column=0, pady=10)
        
        # Password display
        ttk.Label(gen_frame, text="Generated Password:").grid(row=5, column=0, sticky=tk.W)
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(gen_frame, textvariable=self.password_var, width=30, font=("Courier", 12))
        password_entry.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Copy button
        ttk.Button(gen_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).grid(row=6, column=2, padx=5)
        
        # Strength meter
        ttk.Label(gen_frame, text="Strength:").grid(row=7, column=0, sticky=tk.W)
        self.strength_var = tk.StringVar(value="Not evaluated")
        strength_label = ttk.Label(gen_frame, textvariable=self.strength_var)
        strength_label.grid(row=7, column=1, sticky=tk.W)
        
        # 2FA Section
        twofa_frame = ttk.LabelFrame(main_frame, text="Two-Factor Authentication", padding="10")
        twofa_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Button(twofa_frame, text="Generate TOTP Secret", command=self.generate_totp_secret).grid(row=0, column=0, pady=5)
        ttk.Button(twofa_frame, text="Generate TOTP Code", command=self.generate_totp_code).grid(row=0, column=1, pady=5)
        
        self.totp_secret_var = tk.StringVar()
        ttk.Entry(twofa_frame, textvariable=self.totp_secret_var, width=30, state='readonly').grid(row=1, column=0, columnspan=2, pady=5)
        
        self.totp_code_var = tk.StringVar()
        ttk.Entry(twofa_frame, textvariable=self.totp_code_var, width=10, font=("Courier", 12), state='readonly').grid(row=2, column=0, pady=5)
        
        ttk.Button(twofa_frame, text="Verify TOTP", command=self.verify_totp).grid(row=2, column=1, padx=5)
    
    def generate_password(self):
        """Generate a new password and evaluate its strength"""
        try:
            password = self.password_generator.generate_password(
                length=self.length_var.get(),
                use_upper=self.upper_var.get(),
                use_lower=self.lower_var.get(),
                use_digits=self.digit_var.get(),
                use_symbols=self.symbol_var.get(),
                exclude_ambiguous=self.ambiguous_var.get()
            )
            
            self.password_var.set(password)
            self.evaluate_password_strength(password)
            
        except ValueError as e:
            messagebox.showerror("Generation Error", str(e))
    
    def evaluate_password_strength(self, password):
        """Evaluate and display password strength"""
        score = self.strength_evaluator.evaluate_strength(password)
        category, color = self.strength_evaluator.get_strength_category(score)
        self.strength_var.set(f"{category} ({score}%)")
    
    def copy_to_clipboard(self):
        """Copy generated password to clipboard"""
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("No Password", "Generate a password first!")
    
    def generate_totp_secret(self):
        """Generate a new TOTP secret"""
        secret = self.two_fa.generate_secret()
        self.totp_secret_var.set(secret)
        messagebox.showinfo("TOTP Secret", f"New secret generated!\n\nShare this with your authenticator app:\n{secret}")
    
    def generate_totp_code(self):
        """Generate TOTP code from current secret"""
        if not self.totp_secret_var.get():
            messagebox.showwarning("No Secret", "Generate a TOTP secret first!")
            return
        
        self.two_fa.secret = self.totp_secret_var.get()
        code = self.two_fa.generate_totp()
        self.totp_code_var.set(code)
    
    def verify_totp(self):
        """Verify entered TOTP code"""
        if not self.totp_secret_var.get():
            messagebox.showwarning("No Secret", "Generate a TOTP secret first!")
            return
        
        code = self.totp_code_var.get()
        if not code:
            messagebox.showwarning("No Code", "Generate a TOTP code first!")
            return
        
        if self.two_fa.verify_totp(code):
            messagebox.showinfo("Success", "TOTP code verified successfully!")
        else:
            messagebox.showerror("Failure", "Invalid TOTP code!")