import logging
from kyber_py.kyber import Kyber512

# Configure logging: overwrites previous logs on each run.
logging.basicConfig(
    filename='logs/kyber512.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'
)

class KyberKeyExchange:
    """
    Implements the Kyber512 Key Encapsulation Mechanism (KEM) using the kyber_py library.
    
    The class uses:
      - Kyber512.keygen() to generate a key pair (public and secret keys)
      - Kyber512.encaps(pk) to generate a shared key and ciphertext
      - Kyber512.decaps(sk, c) to retrieve the shared key from the ciphertext
    """
    def __init__(self):
        logging.info("Initializing Kyber512 Key Exchange")
        # Generate key pair
        self.public_key, self.secret_key = Kyber512.keygen()
        logging.info("Kyber512 key pair generated")
        logging.info(f"Public Key: {self.public_key.hex()}")
        logging.info(f"Secret Key: {self.secret_key.hex()}")
        # Placeholders for encapsulated values
        self.shared_key = None
        self.ciphertext = None

    def encapsulate(self):
        """
        Encapsulate a shared key using the public key.
        Returns:
            (shared_key, ciphertext)
        """
        logging.info("Starting encapsulation using public key")
        self.shared_key, self.ciphertext = Kyber512.encaps(self.public_key)
        logging.info("Encapsulation complete")
        logging.info(f"Encapsulated Shared Key: {self.shared_key.hex()}")
        logging.info(f"Ciphertext: {self.ciphertext.hex()}")
        return self.shared_key, self.ciphertext

    def decapsulate(self):
        """
        Decapsulate the shared key using the secret key and the ciphertext.
        Returns:
            The shared key derived from decapsulation.
        """
        if self.ciphertext is None:
            logging.error("No ciphertext available: run encapsulate() first.")
            raise ValueError("Ciphertext is not available. Run encapsulate() first.")
        logging.info("Starting decapsulation using secret key")
        derived_key = Kyber512.decaps(self.secret_key, self.ciphertext)
        logging.info("Decapsulation complete")
        logging.info(f"Decapsulated Shared Key: {derived_key.hex()}")
        return derived_key

# Example usage:
if __name__ == "__main__":
    # Initialize key exchange for Kyber512
    exchange = KyberKeyExchange()
    
    # Perform encapsulation (simulate sender side)
    shared_key_enc, ciphertext = exchange.encapsulate()
    
    # Perform decapsulation (simulate receiver side)
    shared_key_dec = exchange.decapsulate()
    
    # Verify that both shared keys match
    if shared_key_enc == shared_key_dec:
        logging.info("Kyber512 Key Exchange Successful: Shared keys match")
        print("Kyber512 Key Exchange Successful.")
    else:
        logging.error("Kyber512 Key Exchange Failed: Shared keys do not match")
        print("Kyber512 Key Exchange Failed: Shared keys do not match.")
