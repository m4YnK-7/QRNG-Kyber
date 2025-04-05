import os
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(
    filename='logs/ecc_log.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'
)

class ECC_Encryption:
    """
    ECC Encryption/Decryption using ECIES-like scheme with AES-GCM.
    
    Supported curves: secp256r1, secp384r1, secp521r1.
    Provides generate_keys(), encrypt(plaintext), and decrypt(ciphertext).
    """
    def __init__(self, curve="secp256r1"):
        self.curve_name = curve
        self._select_curve()
        self.generate_keys()
        logging.info(f"ECC Keys generated using curve {self.curve_name}.")
        # Log public key in hex (serialized)
        pub_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        logging.info(f"Public Key: {pub_bytes.hex()}")

    def _select_curve(self):
        if self.curve_name == "secp256r1":
            self.curve = ec.SECP256R1()
        elif self.curve_name == "secp384r1":
            self.curve = ec.SECP384R1()
        elif self.curve_name == "secp521r1":
            self.curve = ec.SECP521R1()
        else:
            raise ValueError("Unsupported curve. Choose secp256r1, secp384r1, or secp521r1.")

    def generate_keys(self):
        """Generates an ECC key pair."""
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        self.public_key = self.private_key.public_key()

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext using an ephemeral key and AES-GCM.
        
        Returns a byte string consisting of:
          ephemeral_public_key || nonce || ciphertext
        """
        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(self.curve, default_backend())
        ephemeral_public = ephemeral_private.public_key()
        # Compute shared secret: ephemeral_private ECDH with recipient's public key
        shared_secret = ephemeral_private.exchange(ec.ECDH(), self.public_key)
        # Derive symmetric key using HKDF-SHA256
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ECC Encryption",
            backend=default_backend()
        ).derive(shared_secret)
        # Encrypt plaintext using AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        # Serialize ephemeral public key (uncompressed point)
        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        # Package: ephemeral_pub_bytes || nonce || ciphertext
        result = ephemeral_pub_bytes + nonce + ciphertext
        logging.info("Encryption complete.")
        logging.info(f"Ephemeral Public Key: {ephemeral_pub_bytes.hex()}")
        logging.info(f"Nonce: {nonce.hex()}")
        logging.info(f"Ciphertext: {ciphertext.hex()}")
        return result

    def decrypt(self, packaged: bytes) -> bytes:
        """
        Decrypts the packaged ciphertext.
        Expects a byte string of the form: ephemeral_public_key || nonce || ciphertext.
        """
        # Determine the length of the ephemeral public key based on curve
        if self.curve_name == "secp256r1":
            pub_len = 65
        elif self.curve_name == "secp384r1":
            pub_len = 97
        elif self.curve_name == "secp521r1":
            pub_len = 133
        else:
            raise ValueError("Unsupported curve.")
        
        ephemeral_pub_bytes = packaged[:pub_len]
        nonce = packaged[pub_len:pub_len+12]
        ciphertext = packaged[pub_len+12:]
        
        # Load the ephemeral public key
        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(self.curve, ephemeral_pub_bytes)
        # Compute shared secret: own private key ECDH with ephemeral public key
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        # Derive symmetric key using HKDF-SHA256
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ECC Encryption",
            backend=default_backend()
        ).derive(shared_secret)
        # Decrypt using AES-GCM
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        logging.info("Decryption complete.")
        logging.info(f"Nonce: {nonce.hex()}")
        logging.info(f"Ciphertext: {ciphertext.hex()}")
        logging.info(f"Recovered Plaintext: {plaintext}")
        return plaintext

# Example usage:
if __name__ == "__main__":
    ecc = ECC_Encryption(curve="secp256r1")
    plaintext = b"This is a highly secure message."
    encrypted = ecc.encrypt(plaintext)
    decrypted = ecc.decrypt(encrypted)
    print(f"Original: {plaintext}")
    print(f"Decrypted: {decrypted}")
    print(f"Encryption and Decryption successful: {plaintext == decrypted}")
