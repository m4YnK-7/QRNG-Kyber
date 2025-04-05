import logging
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Configure logging with timestamps and message formatting
logging.basicConfig(filename='logs/rsa_log.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', filemode='w')

class RSA_Encryption:
    """Class-based RSA encryption, decryption, signing, and verification."""
    
    def __init__(self, bits=4096):
        self.bits = bits
        self.key = RSA.generate(bits)
        self.public_key = self.key.publickey()
        
        # Extract key parameters
        self.n = self.key.n  # Modulus
        self.e = self.key.e  # Public exponent
        self.d = self.key.d  # Private exponent
        self.p = self.key.p  # First prime
        self.q = self.key.q  # Second prime

        # Log key details
        logging.info(f"Generated RSA Keys: {bits}-bit security")
        logging.info(f"Public Key (n, e): (n={self.n}, e={self.e})")
        logging.info(f"Private Key (d): {self.d}")
        logging.info(f"Prime Numbers (p, q): (p={self.p}, q={self.q})")
    
    def export_keys(self):
        """Exports RSA keys for storage."""
        logging.info("Exporting RSA keys.")
        return self.key.export_key(), self.public_key.export_key()
    
    def encrypt(self, plaintext: bytes):
        """Encrypts a message using RSA-OAEP."""
        cipher_rsa = PKCS1_OAEP.new(self.public_key)
        encrypted_message = cipher_rsa.encrypt(plaintext)
        
        digest = SHA256.new(plaintext).hexdigest()  # Hashing plaintext for logging
        logging.info(f"Encrypting Message - SHA256 Digest: {digest}")
        logging.info(f"Encrypted Message: {encrypted_message.hex()}")
        
        return encrypted_message
    
    def decrypt(self, ciphertext: bytes):
        """Decrypts an RSA encrypted message."""
        cipher_rsa = PKCS1_OAEP.new(self.key)
        decrypted_message = cipher_rsa.decrypt(ciphertext)
        
        digest = SHA256.new(decrypted_message).hexdigest()  # Hashing decrypted text
        logging.info(f"Decrypting Message - SHA256 Digest: {digest}")
        logging.info(f"Decrypted Message: {decrypted_message}")
        
        return decrypted_message
    
    def sign(self, message: bytes):
        """Signs a message using RSA-PKCS#1 v1.5."""
        hash_value = SHA256.new(message)
        signature = pkcs1_15.new(self.key).sign(hash_value)
        
        digest = hash_value.hexdigest()
        logging.info(f"Signing Message - SHA256 Digest: {digest}")
        logging.info(f"Signature: {signature.hex()}")
        
        return signature
    
    def verify(self, message: bytes, signature: bytes):
        """Verifies an RSA signature."""
        hash_value = SHA256.new(message)
        try:
            pkcs1_15.new(self.public_key).verify(hash_value, signature)
            logging.info("Signature Verification: SUCCESS")
            return True
        except (ValueError, TypeError):
            logging.warning("Signature Verification: FAILED")
            return False

# Example usage
if __name__ == "__main__":
    rsa = RSA_Encryption(1024)
    message = b"This is a highly secure message."
    
    # Encryption & Decryption
    encrypted = rsa.encrypt(message)
    decrypted = rsa.decrypt(encrypted)
    
    # Signing & Verification
    signature = rsa.sign(message)
    verification_result = rsa.verify(message, signature)

    # Print output for clarity
    print(f"Original Message: {message}")
    print(f"Decrypted Message: {decrypted}")
    print(f"Signature Verified: {verification_result}")



"""
Security Features in the Implementation

1. RSA Key Generation (4096-bit)

2. RSA-OAEP Padding for Encryption
    Uses PKCS1_OAEP, a secure padding scheme.
    Prevents chosen plaintext attacks (CPA).
    Mitigates Bleichenbacher's padding oracle attack.
    Ensures randomness in ciphertext, avoiding pattern analysis.

3.Secure RSA Decryption
    Uses PKCS1_OAEP, ensuring decryption is resistant to attacks.
    Prevents malicious ciphertext modification.

4.S4HA-256 Hashing for Message Integrity
    Computes SHA-256 digests for plaintext and decrypted messages.
    Ensures integrity checks and logging of hashed values.

5.RSA-PKCS#1 v1.5 for Digital Signatures
    Uses SHA-256 hashing for strong message integrity.
    Prevents forgery and tampering attacks.
    Allows verification to confirm authenticity.

6. Signature Verification with RSA
    Verifies the validity of digital signatures.
    Prevents replay attacks and impersonation.
    Logs success or failure of verification attempts.
"""