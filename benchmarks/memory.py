import tracemalloc
import pandas as pd
import logging
from crypto_algos.classical.rsa import RSA_Encryption
from crypto_algos.classical.ecc import ECC_Encryption
from crypto_algos.classical.dh import DiffieHellmanEncryption

# Configure secure logging for memory benchmarks
logging.basicConfig(
    filename='logs/memory_benchmark.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='w'
)

class BenchmarkMemory:
    def __init__(self, encryption_model, iterations=5):
        """
        Initialize BenchmarkMemory for a given encryption model.

        :param encryption_model: Encryption class (RSA_Encryption, DiffieHellmanEncryption, ECC_Encryption)
        :param iterations: Number of times to repeat the benchmark.
        """
        self.encryption_model = encryption_model
        self.iterations = iterations

    def _measure_memory_usage(self, func, *args, **kwargs):
        """
        Measure the peak memory usage of a given function using tracemalloc.

        :param func: Function to be measured.
        :return: Peak memory usage in MB.
        """
        tracemalloc.start()
        func(*args, **kwargs)  # Execute the function
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        return peak / 1024  # Convert bytes to MB

    def benchmark_rsa_memory(self, key_size):
        """
        Benchmark RSA encryption memory usage.

        :param key_size: RSA key size in bits.
        :return: Pandas DataFrame containing average memory usage results.
        """
        rsa = self.encryption_model(bits=key_size)
        mem_usages = [self._measure_memory_usage(rsa.encrypt, b"Test Message") for _ in range(self.iterations)]
        avg_mem = sum(mem_usages) / self.iterations
        return pd.DataFrame({
            "Key_Size(bits)": [key_size],
            "Avg_Mem_used(KB)": [avg_mem]
        })

    def benchmark_dh_memory(self, param):
        """
        Benchmark Diffie-Hellman memory usage.

        :param param: Predefined DH parameter level.
        :return: Pandas DataFrame containing average memory usage results.
        """
        dh = self.encryption_model(param=param)
        # Using compute_shared_secret with the object's own public key for benchmarking purposes
        mem_usages = [self._measure_memory_usage(dh.compute_shared_secret, dh.public_key) for _ in range(self.iterations)]
        avg_mem = sum(mem_usages) / self.iterations
        return pd.DataFrame({
            "Parameter": [param],
            "Avg_Mem_used(KB)": [avg_mem]
        })

    def benchmark_ecc_memory(self, curve):
        """
        Benchmark ECC encryption memory usage.

        :param curve: ECC curve name.
        :return: Pandas DataFrame containing average memory usage results.
        """
        ecc = self.encryption_model(curve=curve)
        mem_usages = [self._measure_memory_usage(ecc.encrypt, b"Test Message") for _ in range(self.iterations)]
        avg_mem = sum(mem_usages) / self.iterations
        return pd.DataFrame({
            "Curve": [curve],
            "Avg_Mem_used(KB)": [avg_mem],
        })


