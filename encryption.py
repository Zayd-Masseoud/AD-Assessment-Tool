import os
from cryptography.fernet import Fernet

# Generate or load encryption key
ENCRYPTION_KEY_PATH = os.path.join(os.path.dirname(__file__), 'instance', 'secret.key')

def load_or_generate_key():
    """Load encryption key from file or generate a new one."""
    if os.path.exists(ENCRYPTION_KEY_PATH):
        with open(ENCRYPTION_KEY_PATH, 'rb') as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        os.makedirs(os.path.dirname(ENCRYPTION_KEY_PATH), exist_ok=True)
        with open(ENCRYPTION_KEY_PATH, 'wb') as key_file:
            key_file.write(key)
        return key

# Initialize Fernet cipher
CIPHER = Fernet(load_or_generate_key())