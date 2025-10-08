# main.py - Secure Random Password Generator with Two-Step Verification
import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# Add project modules to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from password_generator import SecurePasswordGenerator
from two_factor_auth import TwoFactorAuth
from strength_evaluator import PasswordStrengthEvaluator
from gui_interface import PasswordGeneratorGUI

def main():
    """Main application entry point"""
    try:
        # Initialize core components
        password_generator = SecurePasswordGenerator()
        two_fa = TwoFactorAuth()
        strength_evaluator = PasswordStrengthEvaluator()
        
        # Launch GUI
        root = tk.Tk()
        app = PasswordGeneratorGUI(root, password_generator, two_fa, strength_evaluator)
        root.mainloop()
        
    except Exception as e:
        print(f"Error starting application: {e}")
        messagebox.showerror("Startup Error", f"Failed to start application: {e}")

if __name__ == "__main__":
    main()