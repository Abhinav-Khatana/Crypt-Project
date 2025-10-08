# strength_evaluator.py
import re

class PasswordStrengthEvaluator:
    def __init__(self):
        self.common_passwords = {'password', '123456', 'qwerty', 'letmein', 'welcome'}
    
    def evaluate_strength(self, password):
        """Evaluate password strength and return score 0-100"""
        if not password:
            return 0
        
        score = 0
        length = len(password)
        
        # Length score (up to 30 points)
        score += min(30, (length / 24) * 30)
        
        # Character diversity (up to 40 points)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        diversity_score = (has_upper + has_lower + has_digit + has_symbol) * 10
        score += diversity_score
        
        # Entropy calculation (up to 30 points)
        char_set_size = 0
        if has_lower: char_set_size += 26
        if has_upper: char_set_size += 26
        if has_digit: char_set_size += 10
        if has_symbol: char_set_size += 20
        
        if char_set_size > 0:
            entropy = length * (char_set_size.bit_length())
            score += min(30, (entropy / 180) * 30)
        
        # Penalty for common patterns
        if password.lower() in self.common_passwords:
            score = max(0, score - 50)
        
        return min(100, int(score))
    
    def get_strength_category(self, score):
        """Convert numerical score to strength category"""
        if score >= 76:
            return "Very Strong", "#00ff00"
        elif score >= 51:
            return "Strong", "#aaff00"
        elif score >= 26:
            return "Medium", "#ffff00"
        else:
            return "Weak", "#ff0000"