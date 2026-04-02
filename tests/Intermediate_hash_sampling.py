import json
import os
import sys
import secrets
from Crypto.Hash import SHAKE256

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.auxiliaries import SampleNTT, SamplePolyCBD_eta, PRF_eta

def format_beats(coeffs):
    """
    Formats 256 coefficients into 64 beats of 64-bit padded hex strings.
    Each beat contains 4 coefficients (16 bits each).
    Ordering: [c3][c2][c1][c0] (little-coefficient-first within the beat)
    """
    beats = []
    for i in range(0, 256, 4):
        # We assume coefficients are in range [0, 3328], so 16-bit padding is sufficient.
        # Concatenate 4 coefficients into a 64-bit integer
        beat = (coeffs[i+3] << 48) | (coeffs[i+2] << 32) | (coeffs[i+1] << 16) | coeffs[i]
        beats.append(f"{beat:016X}")
    return beats

def generate_test_vectors():
    results = {
        "version": "1.0",
        "description": "ML-KEM Intermediate Hash Sampling Test Vectors",
        "tests": []
    }

    # --- Test A: NTT Sampler Vectors ---
    # Input Seed: 34 Bytes (rho + i + j)
    seed_a = secrets.token_bytes(34)
    coeffs_a = SampleNTT(seed_a)
    beats_a = format_beats(coeffs_a)

    results["tests"].append({
        "test_id": "Test A",
        "name": "NTT Sampler Vectors (Variable Rate)",
        "input_seed_hex": seed_a.hex().upper(),
        "input_description": "34 Bytes (rho + i + j)",
        "output_beats": beats_a
    })

    # --- Test B: CBD eta=2 (ML-KEM-512) ---
    # Input Seed: 33 Bytes (sigma + b)
    seed_b = secrets.token_bytes(33)
    sigma_b = seed_b[:32]
    b_byte = seed_b[32:33]

    # Expand via PRF
    expanded_b = PRF_eta(2, sigma_b, b_byte)
    coeffs_b = SamplePolyCBD_eta(expanded_b, 2)
    beats_b = format_beats(coeffs_b)

    results["tests"].append({
        "test_id": "Test B",
        "name": "CBD Sampler Vectors (eta=2)",
        "input_seed_hex": seed_b.hex().upper(),
        "config": {"hsu_mode_i": "MODE_SAMPLE_CBD", "is_eta3_i": 0},
        "output_beats": beats_b
    })

    # --- Test C: CBD eta=3 (ML-KEM-768/1024) ---
    # Input Seed: 33 Bytes (sigma + b)
    seed_c = secrets.token_bytes(33)
    sigma_c = seed_c[:32]
    c_byte = seed_c[32:33]

    # Expand via PRF
    expanded_c = PRF_eta(3, sigma_c, c_byte)
    coeffs_c = SamplePolyCBD_eta(expanded_c, 3)
    beats_c = format_beats(coeffs_c)

    results["tests"].append({
        "test_id": "Test C",
        "name": "CBD Sampler Vectors (eta=3)",
        "input_seed_hex": seed_c.hex().upper(),
        "config": {"hsu_mode_i": "MODE_SAMPLE_CBD", "is_eta3_i": 1},
        "output_beats": beats_c
    })

    # --- Test E: Wrapper Smoke Test (SHAKE256 Bypass) ---
    # Input Seed: 32 Bytes
    seed_e = secrets.token_bytes(32)
    hash_e = SHAKE256.new(seed_e).read(32)

    results["tests"].append({
        "test_id": "Test E",
        "name": "Demux/Mux Bypass (SHAKE256)",
        "input_seed_hex": seed_e.hex().upper(),
        "config": {"hsu_mode_i": "MODE_HASH_SHAKE256"},
        "output_hash_hex": hash_e.hex().upper()
    })

    # Save results
    output_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results'))
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'output_hsu_sampling.json')

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Test vectors generated successfully: {output_path}")

if __name__ == "__main__":
    generate_test_vectors()
