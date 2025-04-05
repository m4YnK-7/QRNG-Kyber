# Comparative Analysis of Cryptography Algorihms
# Traditional vs. Lattic-Based vs Lattice with QRNG

A comprehensive cryptography project demonstrating classical algorithms (RSA, ECC, Diffie-Hellman), post-quantum algorithms (Kyber) and QRNG introduced Kyberand benchmarking for execution time and memory usage. This repository also includes a demonstration of quantum randomness (QRNG) integration and a proof-of-concept for breaking RSA using Shor’s Algorithm (simulation).   
  
**This repository is part of my paper**: [Link to paper](https://drive.google.com/file/d/1Pug_LUp9UHtX3nmaHiqzq7_2BUp5lgXl/view?usp=sharing).

## Table of Contents
- [Features](#features)
- [Setup & Installation](#setup--installation)
- [Quantum Randomness (QRNG)](#quantum-randomness-qrng)
- [Shor’s Algorithm Demonstration](#shors-algorithm-demonstration)
- [Benchmarks](#benchmarks)
- [License](#license)
- [Contributions](#contributions)
- [Contact](#contact)

## Features

### Classical Algorithms
- **RSA:** Key generation, encryption/decryption, signing/verifying.
- **ECC:** Key generation, ECIES-style encryption/decryption, signing/verifying.
- **Diffie-Hellman:** Parameterized prime sizes (256, 512, 1024, 2048 bits).

### Post-Quantum Algorithm
- **Kyber:** CRYSTALS-Kyber KEM (Key Encapsulation Mechanism).
- **QRNG-Kyber:** Used QRNG in CRYSTAL-Kyber KEM
  
### Benchmarking
- **Execution Time:** Measured by [`execution_time.py`](benchmarks/execution_time.py)
- **Memory Usage:** Measured by [`memory.py`](benchmarks/memory.py)
- Results are stored in text files (e.g., `benchmark_all_results.txt`, `memory_benchmark_results.txt`).

## Setup & Installation

1. **Clone the Repository**
 ```bash
 git clone https://github.com/your-username/cryptography-project.git
 cd cryptography-project
 ```

2. Create & Activate Python 3.8 Virtual Environment
```bash
# Create a virtual environment using Python 3.8
python3.8 -m venv .venv

# Activate the environment
source .venv/bin/activate      # On Linux/Mac
.venv\Scripts\activate         # On Windows
```

3. Install Dependencies
```bash
pip install -r requirements.txt
```

## Quantum Randomness (QRNG)

This project integrates true quantum randomness via the `qrandom` library, which fetches random numbers from the ANU Quantum Random Number Generator.  
<br>
To get your own API key by signing up at:
[ANU QRNG API KEY](https://quantumnumbers.anu.edu.au/)  
<br>
To configure your API key:
```bash
export QRANDOM_API_KEY="your_api_key_here"
```
Alternatively, you can use the qrandom-init tool to set up your key. Refer to the qrandom documentation for more information.

## Shor's Algorithm Demonstration  
This project includes a simulation of **Shor's Algorithm** using Qiskit to demonstrate how quantum computers can factorize large integers efficiently. It is important to note that this is **only a simulation** and **does not actually break encryption**, as it runs on classical hardware and emulates quantum behavior through the Qiskit framework. Due to deprecation of the original Shor implementation in newer versions of Qiskit, we used **Qiskit version 0.25.0** for compatibility. Make sure to install this specific version if you wish to run the Shor simulation successfully.  

## Benchmarks  
**Note:** These benchmarks were done on my laptop : Intel i7-1165g7 with 16GB RAM  
### A. RSA Benchmarks
| Key Size (bits) | KeyGen Time (s) | Enc Time (s) | Dec Time (s) | Avg Mem Used (KB) |
|-----------------|------------------|---------------|---------------|--------------------|
| 1024            | 0.010407         | 0.001634      | 0.000506      | 5.812695           |
| 2048            | 0.010627         | 0.001472      | 0.001888      | 6.724414           |
| 4096            | 0.015549         | 0.001360      | 0.006928      | 12.93457           |

### B. Diffie-Hellman Benchmarks
| Key Size (bits) | KeyGen Time (s)     | Shared Secret Time (s) | Avg Mem Used (KB) |
|-----------------|----------------------|--------------------------|--------------------|
| 512             | 3.92199e-07          | 0.001546                 | 5.240234           |
| 1024            | 5.05400e-07          | 0.007867                 | 5.882812           |
| 2048            | 4.89800e-07          | 0.00848                  | 5.882812           |

### C. ECC Benchmarks
| Curve       | KeyGen Time (s) | Enc Time (s) | Dec Time (s) | Avg Mem Used (KB) |
|-------------|------------------|---------------|---------------|--------------------|
| secp256r1   | 0.00003          | 0.000381      | 0.000441      | 5.71875            |
| secp384r1   | 0.000137         | 0.000775      | 0.000571      | 5.859375           |
| secp521r1   | 0.000153         | 0.000789      | 0.000878      | 6.017578           |
### D. Kyber Benchmarks
| Parameter | Kyber512 | Kyber768 | Kyber1024 |
|-----------|----------|----------|-----------|
| Keygen (ms) | 7.71     | 14.48    | 21.70     |
| Keygen/s    | 129.68   | 69.07    | 46.08     |
| Encap (ms)  | 10.59    | 17.65    | 25.87     |
| Encap/s     | 94.45    | 56.55    | 39.57     |
| Decap (ms)  | 14.40    | 22.51    | 32.89     |
| Decap/s     | 69.46    | 44.42    | 30.40     |
### E. QRNG Kyber Benchmarks
| Parameter   | Kyber512 | Kyber768 | Kyber1024 |
|-------------|----------|----------|-----------|
| Keygen (ms) | 8.25     | 13.48    | 17.93     |
| Keygen/s    | 121.16   | 74.16    | 55.77     |
| Encap (ms)  | 11.27    | 17.91    | 23.47     |
| Encap/s     | 88.71    | 55.82    | 42.61     |
| Decap (ms)  | 15.99    | 22.57    | 29.87     |
| Decap/s     | 62.55    | 43.72    | 33.51     |



## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.

## Contributions

Pull requests and suggestions are welcome! Please open an issue for major changes to discuss improvements beforehand.

## Contact

For any questions or feedback, feel free to contact **mayanksingh4370@gmail.com** or open an issue in this repository.
