# password_generator.py
import secrets
import string

class SecurePasswordGenerator:
    def __init__(self):
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        
    def generate_password(self, length=16, use_upper=True, use_lower=True, 
                         use_digits=True, use_symbols=True, exclude_ambiguous=True):
        """Generate cryptographically secure random password"""
        character_pool = ""
        
        # Build character pool based on user selections
        if use_lower:
            character_pool += self.char_sets['lowercase']
        if use_upper:
            character_pool += self.char_sets['uppercase']
        if use_digits:
            character_pool += self.char_sets['digits']
        if use_symbols:
            character_pool += self.char_sets['symbols']
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous_chars = 'Il1O0'
            character_pool = ''.join(c for c in character_pool if c not in ambiguous_chars)
        
        # Ensure at least one character type is selected
        if not character_pool:
            raise ValueError("At least one character type must be selected")
        
        # Generate password using cryptographically secure random choices
        password = ''.join(secrets.choice(character_pool) for _ in range(length))
        
        return password