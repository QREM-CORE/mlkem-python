import json
import os
import sys
import secrets
from Crypto.Hash import SHA3_512, SHAKE256, SHA3_256

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.auxiliaries import SampleNTT, SamplePolyCBD_eta, PRF_eta, G

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
        "version": "1.1",
        "description": "ML-KEM Intermediate Hash Sampling Test Vectors",
        "tests": []
    }

    # --- Test A: NTT Sampler (Standard) ---
    rho = secrets.token_bytes(32)
    col, row = 1, 0  # symmetric-ish but standard
    seed_a = rho + bytes([col, row])
    coeffs_a = SampleNTT(seed_a)
    beats_a = format_beats(coeffs_a)

    results["tests"].append({
        "test_id": "Test A",
        "name": "NTT Sampler (Standard)",
        "input_seed_hex": rho.hex().upper(),
        "config": {
            "hsu_mode_i": "MODE_SAMPLE_NTT",
            "ROW": row,
            "COL": col
        },
        "output_beats": beats_a
    })

    # --- Test A2: NTT Sampler (Asymmetric Coords) ---
    # Catch byte-swap bugs in (row, col) injection
    col2, row2 = 5, 2
    seed_a2 = rho + bytes([col2, row2])
    coeffs_a2 = SampleNTT(seed_a2)
    beats_a2 = format_beats(coeffs_a2)

    results["tests"].append({
        "test_id": "Test A2",
        "name": "NTT Sampler (Asymmetric)",
        "input_seed_hex": rho.hex().upper(),
        "config": {
            "hsu_mode_i": "MODE_SAMPLE_NTT",
            "ROW": row2,
            "COL": col2
        },
        "output_beats": beats_a2
    })

    # --- Test B: CBD eta=2 (ML-KEM-512) ---
    seed_b = secrets.token_bytes(33)
    sigma_b = seed_b[:32]
    n_b = seed_b[32:33]
    expanded_b = PRF_eta(2, sigma_b, n_b)
    coeffs_b = SamplePolyCBD_eta(expanded_b, 2)
    beats_b = format_beats(coeffs_b)

    results["tests"].append({
        "test_id": "Test B",
        "name": "CBD Sampler (eta=2)",
        "input_seed_hex": sigma_b.hex().upper(),
        "config": {
            "hsu_mode_i": "MODE_SAMPLE_CBD",
            "is_eta3_i": 0,
            "CBD_N": n_b[0]
        },
        "output_beats": beats_b
    })

    # --- Test C: CBD eta=3 (ML-KEM-768/1024) ---
    seed_c = secrets.token_bytes(33)
    sigma_c = seed_c[:32]
    n_c = seed_c[32:33]
    expanded_c = PRF_eta(3, sigma_c, n_c)
    coeffs_c = SamplePolyCBD_eta(expanded_c, 3)
    beats_c = format_beats(coeffs_c)

    results["tests"].append({
        "test_id": "Test C",
        "name": "CBD Sampler (eta=3)",
        "input_seed_hex": sigma_c.hex().upper(),
        "config": {
            "hsu_mode_i": "MODE_SAMPLE_CBD",
            "is_eta3_i": 1,
            "CBD_N": n_c[0]
        },
        "output_beats": beats_c
    })

    # --- Test D: SHA3-512 Bypass (Regression) ---
    d_input = secrets.token_bytes(32)
    sha512_full = SHA3_512.new(d_input).digest()
    sha512_beats = [sha512_full[i:i+8][::-1].hex().upper() for i in range(0, 64, 8)]
    # Reversed bytes for LE AXI interface
    sha512_beats_le = []
    for i in range(0, 64, 8):
        chunk = sha512_full[i:i+8]
        sha512_beats_le.append(chunk[::-1].hex().upper())

    results["tests"].append({
        "test_id": "Test D",
        "name": "SHA3-512 Bypass (Baseline)",
        "input_seed_hex": d_input.hex().upper(),
        "sigma_expected": sha512_full[32:64].hex().upper(),
        "config": {"hsu_mode_i": "MODE_HASH_SHA3_512"},
        "output_beats": sha512_beats_le
    })

    # --- Test G: CBD from Sigma ---
    # This matches the internal HSU flow: G(d) -> sigma -> PRF(sigma, n)
    d_input_g = secrets.token_bytes(32)
    rho_g, sigma_g = G(d_input_g)
    n_g = bytes([0x07])
    expanded_g = PRF_eta(2, sigma_g, n_g)
    coeffs_g = SamplePolyCBD_eta(expanded_g, 2)
    beats_g = format_beats(coeffs_g)

    results["tests"].append({
        "test_id": "Test G",
        "name": "CBD from Sigma (Flow)",
        "input_seed_hex": d_input_g.hex().upper(),
        "sigma_expected": sigma_g.hex().upper(),
        "config": {
            "hsu_mode_i": "MODE_SAMPLE_CBD",
            "is_eta3_i": 0,
            "CBD_N": 0x07,
            "RUN_G_FIRST": 1 # Flag for TB to run SHA3-512 first
        },
        "output_beats": beats_g
    })

    # --- Test E: SHAKE256 Bypass ---
    seed_e = secrets.token_bytes(32)
    hash_e = SHAKE256.new(seed_e).read(32)
    hash_beats_le = [hash_e[i:i+8][::-1].hex().upper() for i in range(0, 32, 8)]

    results["tests"].append({
        "test_id": "Test E",
        "name": "SHAKE256 Bypass",
        "input_seed_hex": seed_e.hex().upper(),
        "config": {"hsu_mode_i": "MODE_HASH_SHAKE256"},
        "output_beats": hash_beats_le
    })

    # --- Test F: Poly Absorb SHA3-256 (1 poly, deterministic) ---
    # Coefficients 0..255 sequential, 4-per-beat. SHA3-256 of packed bytes.
    # Deterministic: no randomness, hardcoded output preserved from original manual entry.
    poly_coeffs_f = list(range(256))  # coefficients 0..255
    coeff_beats_f = []
    for i in range(0, 256, 4):
        coeff_beats_f.append([poly_coeffs_f[i], poly_coeffs_f[i+1],
                               poly_coeffs_f[i+2], poly_coeffs_f[i+3]])

    results["tests"].append({
        "test_id": "Test F",
        "name": "Poly Absorb SHA3-256 (1 poly)",
        "config": {
            "hsu_mode_i": "MODE_ABSORB_POLY",
            "poly_cnt": 1
        },
        "input_coeffs": coeff_beats_f,
        "output_beats": [
            "945159B9A42EED58",
            "D1C344226B308E18",
            "CEAAF1542CB860E1",
            "C61622E593A5CBC2"
        ]
    })

    # --- Test H: Multi-Phase Absorption (Poly + Seed) ---
    # H(poly || seed). Uses 1 poly and 32 bytes of seed.
    poly_coeffs_h = list(range(256))
    seed_h = secrets.token_bytes(32)
    
    # Pack poly: 12-bit LE, 4 coeffs per 64-bit beat (48 bits used)
    packed_poly = bytearray()
    coeff_beats_h = []
    for i in range(0, 256, 4):
        c = [poly_coeffs_h[i+j] & 0xFFF for j in range(4)]
        coeff_beats_h.append(c)
        val = c[0] | (c[1] << 12) | (c[2] << 24) | (c[3] << 36)
        packed_poly.extend(val.to_bytes(6, 'little'))
    
    # Combined message
    msg_h = packed_poly + seed_h
    hash_h = SHA3_256.new(msg_h).digest()
    hash_beats_h = [hash_h[i:i+8][::-1].hex().upper() for i in range(0, 32, 8)]

    results["tests"].append({
        "test_id": "Test H",
        "name": "Multi Phase Absorption (Poly + Seed)",
        "config": {
            "hsu_mode_i": "MODE_ABSORB_POLY",
            "poly_cnt": 1
        },
        "input_coeffs": coeff_beats_h,
        "input_seed_hex": seed_h.hex().upper(),
        "output_beats": hash_beats_h
    })

    # Save results directly to verif/test_vectors.json
    # Script lives at verif/mlkem-python/tests/ — go up 2 levels to verif/
    output_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..', 'test_vectors.json')
    )
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Test vectors generated successfully: {output_path}")

if __name__ == "__main__":
    generate_test_vectors()
