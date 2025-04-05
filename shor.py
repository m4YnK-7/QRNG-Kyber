import logging
import math
from Crypto.Util.number import inverse
from qiskit import Aer, transpile, assemble, execute
from qiskit.circuit.library import QFT
from qiskit import QuantumCircuit
from qiskit.algorithms import Shor
from crypto_algos.classical.rsa import RSA_Encryption

# Configure logging
logging.basicConfig(filename='logs/shor_attack.log', level=logging.INFO, format='%(asctime)s - %(message)s', filemode='w')

def shor_factorization(N):
    """Uses Qiskit's Shor's Algorithm to factorize the RSA modulus."""
    backend = Aer.get_backend('qasm_simulator')
    shor = Shor(backend)
    result = shor.factor(N)
    if result.success:
        p, q = result.factors[0]  # Extract prime factors
        logging.info(f"Shor's Algorithm found factors: p={p}, q={q}")
        return p, q
    else:
        logging.error("Shor's Algorithm failed to factorize N.")
        return None, None

def attack_rsa():
    """Demonstrates breaking RSA using Shor's Algorithm."""
    rsa = RSA_Encryption(bits=1024)  # Use smaller bits for feasible simulation
    public_key, _ = rsa.export_keys()
    
    # Extract N and e
    N = rsa.n  # Modulus
    e = rsa.e  # Public exponent
    
    logging.info(f"Target RSA Modulus (N): {N}")
    logging.info(f"Public Exponent (e): {e}")

    # Factorize N using Shor's Algorithm
    p, q = shor_factorization(N)
    if not p or not q:
        logging.error("Failed to retrieve factors of N.")
        return
    
    # Compute private exponent d
    phi_n = (p - 1) * (q - 1)
    d = inverse(e, phi_n)

    logging.info(f"Recovered Private Key: d={d}")
    
    # Verify decryption using the cracked private key
    original_message = b"Attack successful"
    encrypted = rsa.encrypt(original_message)
    decrypted = pow(int.from_bytes(encrypted, byteorder='big'), d, N)
    decrypted_message = decrypted.to_bytes((decrypted.bit_length() + 7) // 8, byteorder='big')

    if decrypted_message == original_message:
        logging.info("RSA successfully broken using Shor's Algorithm!")
    else:
        logging.error("Decryption failed with recovered private key.")

if __name__ == "__main__":
    attack_rsa()
