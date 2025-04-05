import pandas as pd
import cProfile
from time import time
from crypto_algos.classical.rsa import RSA_Encryption
from crypto_algos.classical.ecc import ECC_Encryption
from crypto_algos.classical.dh import DiffieHellmanEncryption,DH_PRIME_MAP
from benchmarks.execution_time import BenchmarkClassical
from benchmarks.memory import BenchmarkMemory
from crypto_algos.kyber_py.kyber import Kyber512, Kyber768, Kyber1024
from crypto_algos.qrng_kyber_py.qkyber import qKyber512, qKyber768, qKyber1024

def run_all_benchmarks():
    rsa_mapping = {1: 1024, 2: 2048, 3: 4096}
    dh_mapping = {1: 256, 2: 512, 3: 1024, 4: 2048}
    ecc_mapping = {1: "secp256r1", 2: "secp384r1", 3: "secp521r1"}
    
    output_lines = []
    output_lines.append("========== Cryptographic Benchmarking Results ==========")
    output_lines.append("")
    
    # --- Combined Benchmarks ---
    output_lines.append("----- Combined Execution Time and Memory Usage Benchmarks -----")
    output_lines.append("")
    
    # --- RSA Combined Benchmarks ---
    output_lines.append("=== RSA Combined Benchmarks ===")
    rsa_combined_dfs = []
    exec_bench_rsa = BenchmarkClassical(RSA_Encryption, iterations=5)
    mem_bench_rsa = BenchmarkMemory(RSA_Encryption, iterations=5)
    for param, key_size in rsa_mapping.items():
        # Run RSA execution time benchmark
        exec_df = exec_bench_rsa.benchmark_rsa_single(key_size)
        # Run RSA memory usage benchmark
        mem_df = mem_bench_rsa.benchmark_rsa_memory(key_size)
      
        combined_df = exec_df.merge(mem_df, on="Key_Size(bits)", suffixes=("_exec", "_mem"))
        rsa_combined_dfs.append(combined_df)
    
    for df in rsa_combined_dfs:
        output_lines.append(df.to_string(index=False))
        output_lines.append("")
    
    # --- Diffie-Hellman (DH) Combined Benchmarks ---
    output_lines.append("=== Diffie-Hellman Combined Benchmarks ===")
    dh_combined_dfs = []
    exec_bench_dh = BenchmarkClassical(DiffieHellmanEncryption, iterations=5)
    mem_bench_dh = BenchmarkMemory(DiffieHellmanEncryption, iterations=5)
    for param, prime_size in dh_mapping.items():
        # Run DH execution time benchmark (pass param to select the prime)
        exec_df = exec_bench_dh.benchmark_dh_single(param)
        # Run DH memory usage benchmark
        mem_df = mem_bench_dh.benchmark_dh_memory(param)

        combined_df = exec_df.merge(mem_df, on="Parameter", suffixes=("_exec", "_mem"))
        
        # Rename the column
        combined_df = combined_df.rename(columns={"Parameter": "Key_Size(bits)"})

        # Replace values manually
        mapping = {1: 256, 2: 512, 3: 1024, 4: 2048}
        combined_df["Key_Size(bits)"] = combined_df["Key_Size(bits)"].map(mapping)
        dh_combined_dfs.append(combined_df)

    
    for df in dh_combined_dfs:
        output_lines.append(df.to_string(index=False))
        output_lines.append("")
    
    # --- ECC Combined Benchmarks ---
    output_lines.append("=== ECC Combined Benchmarks ===")
    ecc_combined_dfs = []
    exec_bench_ecc = BenchmarkClassical(ECC_Encryption, iterations=5)
    mem_bench_ecc = BenchmarkMemory(ECC_Encryption, iterations=5)
    for param, curve in ecc_mapping.items():
        # Run ECC execution time benchmark
        exec_df = exec_bench_ecc.benchmark_ecc_single(curve)
        # Run ECC memory usage benchmark
        mem_df = mem_bench_ecc.benchmark_ecc_memory(curve)
        
        combined_df = exec_df.merge(mem_df, on="Curve", suffixes=("_exec", "_mem"))
        ecc_combined_dfs.append(combined_df)
    
    for df in ecc_combined_dfs:
        output_lines.append(df.to_string(index=False))
        output_lines.append("")
    
    output_lines.append("-"*80)
    output_lines.append("")

    
    # --- Kyber Benchmarks ---
    output_lines.append("====== Kyber Benchmarking ======")
    output_lines.append("")
    
    # Prepare table header for Kyber results
    header = f"{'Params':^11} | {'keygen':^8} | {'keygen/s':^9} | {'encap':^7} | {'encap/s':^9} | {'decap':^7} | {'decap/s':^8}"
    separator = "-" * len(header)
    output_lines.append(header)
    output_lines.append(separator)
    
    count = 100  # number of iterations for benchmarking Kyber
    
    def benchmark_kyber(Kyber, name):
        keygen_times, enc_times, dec_times = [], [], []
        for _ in range(count):
            t0 = time()
            pk, sk = Kyber.keygen()
            keygen_times.append(time() - t0)
    
            t1 = time()
            key, c = Kyber.encaps(pk)
            enc_times.append(time() - t1)
    
            t2 = time()
            Kyber.decaps(sk, c)
            dec_times.append(time() - t2)
    
        avg_keygen = sum(keygen_times) / count
        avg_enc = sum(enc_times) / count
        avg_dec = sum(dec_times) / count
        
        keygen_ms = avg_keygen * 1000
        enc_ms = avg_enc * 1000
        dec_ms = avg_dec * 1000
        
        keygen_rate = 1 / avg_keygen if avg_keygen > 0 else 0
        enc_rate = 1 / avg_enc if avg_enc > 0 else 0
        dec_rate = 1 / avg_dec if avg_dec > 0 else 0
        
        return f"{name:^11} | {keygen_ms:8.2f}ms | {keygen_rate:9.2f} | {enc_ms:7.2f}ms | {enc_rate:9.2f} | {dec_ms:7.2f}ms | {dec_rate:8.2f}"
    

    kyber_results = [
        benchmark_kyber(Kyber512, "Kyber512"),
        benchmark_kyber(Kyber768, "Kyber768"),
        benchmark_kyber(Kyber1024, "Kyber1024"),
    ]
    
    output_lines.extend(kyber_results)
    
    output_lines.append("")
    output_lines.append("-"*80)


    output_lines.append("====== QRNG Kyber Benchmarking ======")
    output_lines.append("")
    
    # Prepare table header for Kyber results
    header = f"{'Params':^11} | {'keygen':^8} | {'keygen/s':^9} | {'encap':^7} | {'encap/s':^9} | {'decap':^7} | {'decap/s':^8}"
    separator = "-" * len(header)
    output_lines.append(header)
    output_lines.append(separator)

    qkyber_results = [
        benchmark_kyber(qKyber512, "Kyber512"),
        benchmark_kyber(qKyber768, "Kyber768"),
        benchmark_kyber(qKyber1024, "Kyber1024"),
    ]

    output_lines.extend(qkyber_results)
    
    
    # Save all results to file
    with open("benchmark_all_results.txt", "w") as f:
        f.write("\n".join(output_lines))
    
    print("Benchmarking complete. Results stored in benchmark_all_results.txt")

if __name__ == "__main__":
    run_all_benchmarks()
