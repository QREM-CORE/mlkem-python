
# ML-KEM FIPS 203 Implementation & Validation Suite

A Python implementation of **ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)** compliant with the **NIST FIPS 203** standard, with a validation pipeline built around official **NIST Known Answer Tests (KAT)**.

---

## Overview

ML-KEM is a post-quantum key encapsulation mechanism standardized by NIST. This implementation covers:

- **Key Generation** — generate ML-KEM key pairs
- **Encapsulation** — produce a ciphertext and shared secret
- **Decapsulation** — recover the shared secret from a ciphertext
- **NIST Validation** — byte-for-byte comparison against official KAT vectors

**Current support:** ML-KEM-768 (KAT vectors 26–50)

---

## Project Structure

```
mlkem-python-implementation/
├── LICENSE
├── README.md
├── requirements.txt
│
├── docs/
│   ├── NIST.FIPS.203.pdf
│   └── repo_folder_structure.txt
│
├── src/mlkem/                        ← core library
│   ├── __init__.py
│   ├── auxiliaries.py
│   ├── Internal_kpke.py
│   ├── internal_mlkem.py
│   └── trace_auxiliaries.py
│
├── vectors/
│   ├── ML-KEM-KeyGen-FIPS203/
│   └── ML-KEM-encapDecap-FIPS203/
│
├── scripts/
│   ├── gen_keygen_vectors.py
│   ├── gen_ntt_radix4_vectors.py
│   └── gen_encrypt_vectors.py
│
├── tests/
│   ├── test_keygen.py
│   ├── test_encap.py
│   ├── test_decap.py
│   └── compare_results.py
│
└── results/
    ├── mlkem_768_results.json
    ├── mlkem_768_encap_results.json
    ├── mlkem_768_decap_results.json
    ├── comp_decomp_results.json
    ├── output_ntt_radix_4_2.json
    └── ...
```

---

## Getting Started

### Prerequisites

- Python 3.8+

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/mlkem-python-implementation.git
   cd mlkem-python-implementation
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

---

## Running Tests

Run all tests from the project root directory.

### Key Generation Validation

Validates key generation against NIST reference vectors:

```bash
python tests/test_keygen.py
```

**Output:** `results/mlkem_768_results.json`

### Encapsulation Validation

Validates encapsulation against NIST vectors:

```bash
python tests/test_encap.py
```

**Output:** `results/mlkem_768_encap_results.json`

### Decapsulation Validation

Validates decapsulation against NIST vectors:

```bash
python tests/test_decap.py
```

**Output:** `results/mlkem_768_decap_results.json`

### Compare Results

Compares generated encapsulation/decapsulation key outputs against expected NIST values (tcId 26–50):

```bash
python tests/compare_results.py
```

---

## Test Coverage

- **Security level:** ML-KEM-768
- **Test range:** KAT vectors 26–50
- **Validation:** Byte-for-byte comparison against NIST official vectors

---

## References

- [NIST FIPS 203 Standard](docs/NIST.FIPS.203.pdf)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## Purpose

This repository is intended for **educational use** — to study and understand the internal mechanics of ML-KEM as specified in FIPS 203.

---

## Contributing

Contributions are welcome. Feel free to open an issue or submit a pull request.

---

## Disclaimer

This is an educational implementation. For production use, rely on audited and certified cryptographic libraries.
=======
# mlkem-python

[![FIPS 203 Compliant](https://img.shields.io/badge/NIST-FIPS_203_Compliant-green)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
![Made with Python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg?style=flat-square&logo=python&logoColor=white)

A clean, pure-Python implementation of **ML-KEM** (Module-Lattice Key Encapsulation Mechanism), as standardized in **FIPS 203**.

ML-KEM (formerly known as Kyber) is a post-quantum cryptographic algorithm designed to be secure against attacks from both classical and quantum computers.

## Features

- **Full FIPS 203 Compliance**: Implements the internal processes (KeyGen, Encaps, Decaps) and the K-PKE layer as specified in the standard.
- **Support for All Security Levels**: Compatible with parameter sets for:
  - **ML-KEM-512** (Security Category 1)
  - **ML-KEM-768** (Security Category 3)
  - **ML-KEM-1024** (Security Category 5)
- **Pure Python**: Easy to read and educational implementation.
- **Dependency**: Uses `pycryptodome` for high-performance SHA-3 and SHAKE primitives.

## Installation

This project requires Python 3.9+ and the `pycryptodome` library.

```bash
pip install pycryptodome
```

## Usage

### Defining Parameters

You can define the parameter sets for ML-KEM as follows:

```python
class MLKEM768:
    k = 3
    eta1 = 2
    eta2 = 2
    du = 10
    dv = 4
```

### Key Generation

```python
from mlkem.internal_mlkem import INTERNAL_ML_KEM_KeyGen
import os

# Generate random seeds
d = os.urandom(32)
z = os.urandom(32)

# Generate encapsulation and decapsulation keys
ek, dk = INTERNAL_MLKEM_KeyGen(d, z, MLKEM768)
```

### Encapsulation

```python
from mlkem.internal_mlkem import INTERNAL_MLKEM_Encaps

# Message to encapsulate (usually random)
m = os.urandom(32)

# Encapsulate and get shared key K and ciphertext c
K, c = INTERNAL_MLKEM_Encaps(ek, m, MLKEM768)
```

### Decapsulation

```python
from mlkem.internal_mlkem import INTERNAL_MLKEM_Decaps

# Decapsulate to recover the shared key K
K_prime = INTERNAL_MLKEM_Decaps(dk, c, MLKEM768)

assert K == K_prime
```

## Repository Structure

- `src/mlkem/`: Core implementation files.
  - `internal_mlkem.py`: Top-level ML-KEM algorithms (Alg 16-18).
  - `Internal_kpke.py`: Public Key Encryption layer (Alg 13-15).
  - `auxiliaries.py`: Helper functions, NTT, and cryptographic primitives.
- `tests/`: Unit tests and NIST test vectors.
- `docs/`: Reference documentation, including the NIST FIPS 203 PDF.

## Testing

The implementation includes a test suite that verifies correctness against NIST test vectors.

```bash
python tests/test_sample.py
```

## References

- [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
