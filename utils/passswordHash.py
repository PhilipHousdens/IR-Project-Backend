import bcrypt  # Import bcrypt for hashing and verification

# Utility function to hash passwords
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Utility function to verify password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        print(f"Invalid salt or corrupted hash for: {hashed_password}")
        return False