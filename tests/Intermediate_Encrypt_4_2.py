import json
import os
import sys
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_Encaps
from mlkem import auxiliaries

class MLKEM768:
    k    = 3
    eta1 = 2
    eta2 = 2
    q    = 3329
    n    = 256
    du   = 10
    dv   = 4

PROMPT_FILE   = 'ML-KEM-encapDecap-FIPS203/prompt.json'
EXPECTED_FILE = 'ML-KEM-encapDecap-FIPS203/expectedResults.json'
OUTPUT_FILE   = 'results/output_intt_radix_4_2.json'

# =============================================================================
# === Helpers
# =============================================================================

def compact_json_dumps(obj):
    """Integer arrays on one line, everything else indented."""
    res = json.dumps(obj, indent=2)
    return re.sub(
        r'\[\s+((?:-?\d+,\s+)*-?\d+)\s+\]',
        lambda m: '[' + re.sub(r'\s+', ' ', m.group(1)) + ']',
        res
    )

def organize_intt_rom_passes(stage_traces):
    """
    Reorganizes intt_stage_traces into ROM hardware pass structure.

    Each Radix-4/2 INTT call (Algorithm 6) produces 5 entries:
        [0] stage="input"      raw NTT-domain polynomial before any butterfly
        [1] stage="r2_first"   after ROM2 first Radix-2 pass  (stride=2)
        [2] stage="r4_pass_2"  after ROM1 Radix-4 pass p=1   (stride=4)
        [3] stage="r4_pass_3"  after ROM1 Radix-4 pass p=2   (stride=16)
        [4] stage="r4_pass_4"  after ROM1 Radix-4 pass p=3   (stride=64)

    For ML-KEM-768 Encaps, expect 4 calls per test:
        intt_index 0..2  ->  u[0], u[1], u[2]  (NTT_inv of A^T * y per dimension)
        intt_index 3     ->  v                  (NTT_inv of t_hat * y)
    """
    rom_output = []
    num_calls  = len(stage_traces) // 5

    for intt_index in range(num_calls):
        chunk = stage_traces[intt_index * 5 : (intt_index + 1) * 5]

        if len(chunk) != 5:
            print(f"  Warning: intt_index={intt_index} incomplete ({len(chunk)}/5 entries). Skipping.")
            continue

        if chunk[0].get("stage") != "input":
            print(f"  Warning: intt_index={intt_index} first entry is not 'input'. Skipping.")
            continue

        if intt_index < MLKEM768.k:
            poly_label = f"u[{intt_index}]"
        else:
            poly_label = "v"

        rom_output.append({
            "intt_index":     intt_index,
            "poly":           poly_label,
            "direction":      "inverse",
            "input":          chunk[0]["coeffs"],
            "ROM2_OMEGA_INV": {
                "first_radix2": chunk[1]["coeffs"]
            },
            "ROM1_R4INTT": {
                "pass_1": chunk[2]["coeffs"],
                "pass_2": chunk[3]["coeffs"],
                "pass_3": chunk[4]["coeffs"]
            }
        })

    return rom_output

# =============================================================================
# === Main
# =============================================================================

def verify_encaps_with_intt(prompt_path, expected_path):
    with open(prompt_path, 'r') as f:
        data = json.load(f)

    try:
        with open(expected_path, 'r') as f:
            expected_data = json.load(f)
        expected_lookup = {
            t['tcId']: t for g in expected_data.get("testGroups", [])
            for t in g.get("tests", [])
        }
    except FileNotFoundError:
        expected_lookup = {}
        print("Warning: expectedResults.json not found. Skipping live comparison.")

    results = {
        "vsId":       data.get("vsId"),
        "algorithm":  data.get("algorithm"),
        "testGroups": []
    }

    print(f"{'tcId':<6} | {'K status':<10} | {'c status':<10} | {'INTT calls':<10}")
    print("-" * 50)

    for group in data.get("testGroups", []):
        if group.get("parameterSet") != "ML-KEM-768":
            continue

        new_group = {
            "tgId":         group.get("tgId"),
            "parameterSet": group.get("parameterSet"),
            "tests":        []
        }

        for test in group.get("tests", []):
            tcid = test.get("tcId")

            if not (26 <= tcid <= 50):
                continue

            ek_bytes = bytes.fromhex(test.get("ek"))
            m_bytes  = bytes.fromhex(test.get("m"))

            # Clear traces before each Encaps call
            auxiliaries.intt_stage_traces.clear()

            # Run Encapsulation — NTT_inv fires inside here
            K, c = INTERNAL_MLKEM_Encaps(ek_bytes, m_bytes, MLKEM768)

            actual_k = K.hex().upper()
            actual_c = c.hex().upper()

            # Comparison
            k_status = "PASS"
            c_status = "PASS"
            if tcid in expected_lookup:
                if actual_k != expected_lookup[tcid].get("k", "").upper():
                    k_status = "FAIL"
                if actual_c != expected_lookup[tcid].get("c", "").upper():
                    c_status = "FAIL"

            # Capture INTT intermediates
            intt_rom_passes = organize_intt_rom_passes(list(auxiliaries.intt_stage_traces))

            print(f"{tcid:<6} | {k_status:<10} | {c_status:<10} | {len(intt_rom_passes):<10}")

            new_group["tests"].append({
                "tcId":            tcid,
                "ek":              test.get("ek").upper(),
                "m":               test.get("m").upper(),
                "c":               actual_c,
                "k":               actual_k,
                "k_status":        k_status,
                "c_status":        c_status,
                "intt_rom_passes": intt_rom_passes
            })

        results["testGroups"].append(new_group)

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        f.write(compact_json_dumps(results))

    print(f"\nResults with INTT intermediates saved to {OUTPUT_FILE}")

# =============================================================================
# === Entry Point
# =============================================================================

verify_encaps_with_intt(PROMPT_FILE, EXPECTED_FILE)