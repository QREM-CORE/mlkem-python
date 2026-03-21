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
