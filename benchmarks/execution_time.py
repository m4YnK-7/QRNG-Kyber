import time
import pandas as pd

class BenchmarkClassical:
    """
    Benchmarking for:
      - RSA (512, 1024, 2048, 4096 bits)
      - DH (512, 1024, 2048, 4096-bit primes)
      - ECC (secp256r1, secp384r1, secp521r1 curves)
    Generates a matrix of execution times.
    """

    def __init__(self, encryption_model, iterations=5):
        """
        :param encryption_model: The encryption model class (RSA, DH, ECC)
        :param iterations: Number of times to repeat the benchmark for averaging
        """
        self.encryption_model = encryption_model
        self.iterations = iterations

    def benchmark_rsa_single(self, key_size):
        """Benchmark RSA for a specific key size."""
        times_keygen = []
        times_enc = []
        times_dec = []

        for _ in range(self.iterations):
            rsa = self.encryption_model(bits=key_size)  

            start = time.perf_counter()
            rsa.export_keys()
            end = time.perf_counter()
            times_keygen.append(end - start)

            plaintext = b"Benchmarking RSA"
            start = time.perf_counter()
            ciphertext = rsa.encrypt(plaintext)
            end = time.perf_counter()
            times_enc.append(end - start)

            start = time.perf_counter()
            rsa.decrypt(ciphertext)
            end = time.perf_counter()
            times_dec.append(end - start)

        avg_keygen = sum(times_keygen) / self.iterations
        avg_enc = sum(times_enc) / self.iterations
        avg_dec = sum(times_dec) / self.iterations
        result = [[key_size, avg_keygen, avg_enc, avg_dec]]

        return pd.DataFrame(result, columns=["Key_Size(bits)", "KeyGen_Time", "Enc_Time", "Dec_Time"])

    def benchmark_dh_single(self, param):
        """
        Benchmark Diffie-Hellman for a specific parameter value.
        The parameter selects the hard-coded prime (e.g., 1->256-bit, 2->512-bit, 3->1024-bit, 4->2048-bit).
        """
        times_keygen = []
        times_shared = []

        for _ in range(self.iterations):
            # Create two instances (Alice and Bob) using the same parameter
            dh_A = self.encryption_model(param=param)
            dh_B = self.encryption_model(param=param)

            # Key generation is performed in __init__; measure retrieval time (negligible, but recorded)
            start = time.perf_counter()
            priv_A, pub_A = dh_A.private_key, dh_A.public_key
            priv_B, pub_B = dh_B.private_key, dh_B.public_key
            end = time.perf_counter()
            times_keygen.append(end - start)

            # Compute shared secrets between the two parties (only pass the other party's public key)
            start = time.perf_counter()
            shared_A = dh_A.compute_shared_secret(pub_B)
            shared_B = dh_B.compute_shared_secret(pub_A)
            end = time.perf_counter()
            times_shared.append(end - start)

            # Optionally, assert that shared_A == shared_B here

        avg_keygen = sum(times_keygen) / self.iterations
        avg_shared = sum(times_shared) / self.iterations
        result = [[param, avg_keygen, avg_shared]]
        return pd.DataFrame(result, columns=["Parameter", "KeyGen_Time", "Shared_Secret_Time"])


    def benchmark_ecc_single(self, curve):
        """Benchmark ECC for a specific curve."""
        times_keygen = []
        times_enc = []
        times_dec = []

        for _ in range(self.iterations):
            ecc = self.encryption_model(curve=curve)

            start = time.perf_counter()
            ecc.generate_keys()
            end = time.perf_counter()
            times_keygen.append(end - start)

            plaintext = b"Benchmarking ECC"
            start = time.perf_counter()
            ciphertext = ecc.encrypt(plaintext)
            end = time.perf_counter()
            times_enc.append(end - start)

            start = time.perf_counter()
            ecc.decrypt(ciphertext)
            end = time.perf_counter()
            times_dec.append(end - start)

        avg_keygen = sum(times_keygen) / self.iterations
        avg_enc = sum(times_enc) / self.iterations
        avg_dec = sum(times_dec) / self.iterations
        result = [[curve, avg_keygen, avg_enc, avg_dec]]

        return pd.DataFrame(result, columns=["Curve", "KeyGen_Time", "Enc_Time", "Dec_Time"])
