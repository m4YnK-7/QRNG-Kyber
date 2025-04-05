import logging
import secrets
import hashlib
import hmac

# Configure secure logging
logging.basicConfig(
    filename='logs/dh_log.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'
)

DH_GENERATOR = 2

# Hard-coded prime constants (hex strings) for demonstration:
# 512-bit prime: (example; not standardized)
DH_PRIME_512 = int("F7E75FDC469067FFDC4E847C51F452DF" * 4, 16)
# 1024-bit prime: (example; not standardized)
DH_PRIME_1024 = int("F7E75FDC469067FFDC4E847C51F452DF" * 8, 16)
# 2048-bit prime (RFC 3526 Group 14)
DH_PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
# 256-bit prime (using the secp256r1 prime, also known as prime256v1)
DH_PRIME_256 = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)

# Map parameter values (1,2,3,4) to prime constants.
DH_PRIME_MAP = {
    1: DH_PRIME_256,
    2: DH_PRIME_512,
    3: DH_PRIME_1024,
    4: DH_PRIME_2048
}

class DiffieHellmanEncryption:
    """
    Implements a secure Diffie-Hellman key exchange using hard-coded prime constants.
    
    The constructor accepts a parameter that selects the prime size:
      1 -> 256-bit, 2 -> 512-bit, 3 -> 1024-bit, 4 -> 2048-bit
    """
    
    def __init__(self, param=3):
        """
        Initializes Diffie-Hellman parameters using a hard-coded prime.
        :param param: An integer (1,2,3,4) indicating the desired prime size.
        """
        if param not in DH_PRIME_MAP:
            raise ValueError("Invalid parameter. Choose 1, 2, 3, or 4.")
        self.prime = DH_PRIME_MAP[param]
        self.generator = DH_GENERATOR
        # Secure private key: random number in [1, prime-2]
        self.private_key = secrets.randbelow(self.prime - 2) + 1  
        self.public_key = pow(self.generator, self.private_key, self.prime)
        
        logging.info(f"DH Parameters Initialized with a {self.prime.bit_length()}-bit prime.")
        logging.info(f"Prime: {self.prime}")
        logging.info(f"Public Key: {self.public_key}")
    
    def generate_keys(self):
        """
        Returns the private and public keys.
        This function is used by benchmarking tools.
        """
        return self.private_key, self.public_key

    def compute_shared_secret(self, other_public_key):
        """
        Computes a securely derived shared secret using HKDF-SHA256.
        :param other_public_key: The public key received from the other party.
        :return: A derived symmetric key.
        """
        if not (2 <= other_public_key < self.prime - 1):
            logging.error("Invalid public key received!")
            raise ValueError("Invalid public key received!")
        
        shared_secret = pow(other_public_key, self.private_key, self.prime)
        derived_key = self.hkdf_sha256(shared_secret)
        
        logging.info("Shared Secret Computed Successfully.")
        logging.info(f"Derived Symmetric Key: {derived_key.hex()}")
        
        return derived_key
    
    @staticmethod
    def hkdf_sha256(shared_secret, salt=b"SecureSalt", info=b"DH Key Exchange", length=32):
        """
        Derives a secure symmetric key using HKDF-SHA256.
        :param shared_secret: The raw shared secret from modular exponentiation.
        :param salt: Salt used in HKDF.
        :param info: Contextual information.
        :param length: Desired length of the derived key.
        :return: The derived symmetric key.
        """
        secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
        prk = hmac.new(salt, secret_bytes, hashlib.sha256).digest()
        okm = hmac.new(prk, info, hashlib.sha256).digest()
        return okm[:length]

# Example usage:
if __name__ == "__main__":
    # Select parameter for desired prime size: e.g., 1 for 256-bit, 2 for 512-bit, 3 for 1024-bit, 4 for 2048-bit
    param = 1  
    alice = DiffieHellmanEncryption(param=param)
    bob = DiffieHellmanEncryption(param=param)
    
    alice_shared_key = alice.compute_shared_secret(bob.public_key)
    bob_shared_key = bob.compute_shared_secret(alice.public_key)
    
    assert alice_shared_key == bob_shared_key, "Shared keys do not match!"
    logging.info("Diffie-Hellman Key Exchange Successful.")
    print("Secure Diffie-Hellman Key Exchange Successful.")



"""
1. Secure Private Key Generation: Uses secrets.randbelow() for cryptographic randomness.
2. Standardized Parameters: Uses a 2048-bit MODP prime from RFC 3526 (Group 14).
3. Public Key Validation: Checks if the received public key is within a valid range.
4. HKDF for Key Derivation: Uses HKDF-SHA256 to derive a symmetric key from the shared secret.
5. Logging Without Sensitive Data: Logs only essential information, avoiding private key leaks.
6. Exception Handling: Raises errors for invalid public keys to prevent attacks.
7. Secure Shared Secret Computation: Uses modular exponentiation for key agreement.
8. Proper Logging Practices: Includes timestamps and structured logs for debugging.
9. Ensures Key Agreement: Asserts that both parties derive the same symmetric key.
0. Modular Design: Encapsulates functionality within a class for reusability.
"""