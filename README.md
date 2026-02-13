# 🔐 ML-KEM FIPS 203 Implementation & Validation Suite

A complete Python implementation of **ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)**, fully compliant with the **NIST FIPS 203** standard.

This project includes a comprehensive validation pipeline built around official **NIST Known Answer Tests (KAT)** to verify cryptographic operations against reference vectors.

---

## 📋 Overview

ML-KEM is a post-quantum cryptographic algorithm standardized by NIST. This implementation provides:

- ✅ **Key Generation** - Generate ML-KEM key pairs
- ✅ **Encapsulation** - Encrypt shared secrets
- ✅ **Decapsulation** - Decrypt shared secrets
- ✅ **NIST Validation** - Byte-for-byte verification against official test vectors

**Current Support:** Security level 768 (KAT vectors 26-50)

---

## 📁 Project Structure

```
mlkem-python-implementation/
├── docs/
│   ├── NIST.FIPS.203.pdf              # FIPS 203 standard reference
│   └── repo_folder_structure.txt      # Folder structure notes
│
├── src/
│   └── mlkem/                         # Core ML-KEM implementation
│       ├── auxiliaries.py             # Helper functions (encoding, math utils)
│       ├── internal_kpke.py           # Internal K-PKE logic
│       └── internal_mlkem.py          # ML-KEM core algorithms
│
├── tests/                             # Test suite
│   ├── ML-KEM-KeyGen-FIPS203/         # Official KeyGen test vectors
│   ├── ML-KEM-encapDecap-FIPS203/     # Official Encap/Decap test vectors
│   ├── Key-Gen-Test.py                # Key generation validation
│   ├── Encrypt-Test.py                # Encapsulation validation
│   ├── Decrypt-Test.py                # Decapsulation validation
│   ├── Intermediate_Generator_KeyGen.py  # Intermediate vector generator
│   └── test_gem.py                    # File comparison utility
│
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

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

## 🧪 Running Tests

### Key Generation Validation

Validates key generation against NIST reference vectors:

```bash
python tests/Key-Gen-Test.py
```

**Output:** `tests/results/mlkem_768_results.json`

### Encapsulation Validation

Validates encapsulation (encryption) against NIST vectors:

```bash
python tests/Encrypt-Test.py
```

**Output:** `tests/results/mlkem_768_encap_results.json`

### Decapsulation Validation

Validates decapsulation (decryption) against NIST vectors:

```bash
python tests/Decrypt-Test.py
```

**Output:** `tests/results/mlkem_768_decap_results.json`

### Generate Intermediate Vectors

Creates intermediate test vectors for debugging:

```bash
python tests/Intermediate_Generator_KeyGen.py
```

### Compare Results

Compare generated results with expected outputs:

```bash
python tests/test_gem.py
```

*Note: Edit `test_gem.py` to specify which files to compare (currently supports KeyGen comparison only)*

---

## 📊 Test Coverage

- **Security Level:** 768 (ML-KEM-768)
- **Test Range:** KAT vectors 26-50
- **Validation:** Byte-for-byte comparison with NIST official vectors

---

## 📚 References

- [NIST FIPS 203 Standard](docs/NIST.FIPS.203.pdf)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)

---

## 🎯 Purpose

This repository is designed for **educational purposes** to understand the implementation details of ML-KEM as specified in FIPS 203.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## ⚠️ Disclaimer

This is an educational implementation. For production use, please rely on audited and certified cryptographic libraries.