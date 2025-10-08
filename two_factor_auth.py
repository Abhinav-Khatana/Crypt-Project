# two_factor_auth.py
import secrets
import time
import hmac
import hashlib
import base64
import struct

class TwoFactorAuth:
    def __init__(self, secret=None):
        self.secret = secret or self.generate_secret()
    
    def generate_secret(self, length=20):
        """Generate a base32 secret for TOTP"""
        random_bytes = secrets.token_bytes(length)
        secret = base64.b32encode(random_bytes).decode('utf-8')
        return secret.rstrip('=')
    
    def generate_totp(self, time_interval=30):
        """Generate time-based one-time password"""
        current_time = int(time.time()) // time_interval
        time_bytes = struct.pack(">Q", current_time)
        
        # HMAC-SHA1 calculation
        secret_bytes = base64.b32decode(self.secret + '=' * ((8 - len(self.secret) % 8) % 8))
        hmac_hash = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
        
        # Dynamic truncation
        offset = hmac_hash[-1] & 0xf
        code = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7fffffff
        
        # Generate 6-digit code
        totp = code % 1000000
        return str(totp).zfill(6)
    
    def verify_totp(self, code, time_interval=30, window=1):
        """Verify TOTP code with time window"""
        current_time = int(time.time()) // time_interval
        
        for i in range(-window, window + 1):
            test_time = current_time + i
            time_bytes = struct.pack(">Q", test_time)
            
            secret_bytes = base64.b32decode(self.secret + '=' * ((8 - len(self.secret) % 8) % 8))
            hmac_hash = hmac.new(secret_bytes, time_bytes, hashlib.sha1).digest()
            
            offset = hmac_hash[-1] & 0xf
            test_code = struct.unpack(">I", hmac_hash[offset:offset+4])[0] & 0x7fffffff
            test_code = test_code % 1000000
            
            if str(test_code).zfill(6) == code:
                return True
        
        return False