import json
import os
import sys

# Update the path to your source directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_Encaps

class MLKEM768:
    k = 3
    eta1 = 2
    eta2 = 2
    q = 3329
    n = 256
    du = 10
    dv = 4

# Paths - Update these to match your actual file names
PROMPT_FILE = 'tests/ML-KEM-encapDecap-FIPS203/prompt.json'
EXPECTED_FILE = 'tests/ML-KEM-encapDecap-FIPS203/expectedResults.json'
OUTPUT_FILE = 'tests/results/mlkem_768_encap_results.json'

def verify_mlkem_encap_range(prompt_path, expected_path):
    with open(prompt_path, 'r') as f:
        data = json.load(f)
    
    # Load expected results for live comparison
    try:
        with open(expected_path, 'r') as f:
            expected_data = json.load(f)
        # Flatten expected tests into a lookup dict {tcId: {c, k}}
        expected_lookup = {
            t['tcId']: t for g in expected_data.get("testGroups", []) 
            for t in g.get("tests", [])
        }
    except FileNotFoundError:
        expected_lookup = {}
        print("Warning: ExpectedResult.json not found. Skipping live comparison.")

    results = {
        "vsId": data.get("vsId"),
        "algorithm": data.get("algorithm"),
        "testResults": []
    }

    print(f"{'tcId':<6} | {'Shared Secret (K)':<12} | {'Ciphertext (c)':<12}")
    print("-" * 45)

    for group in data.get("testGroups", []):
        if group.get("parameterSet") != "ML-KEM-768":
            continue

        for test in group.get("tests", []):
            tcid = test.get("tcId")
            
            # --- FILTER FOR RANGE 26 to 50 ---
            if 26 <= tcid <= 50:
                ek_bytes = bytes.fromhex(test.get("ek"))
                m_bytes = bytes.fromhex(test.get("m"))

                # Run Encapsulation
                K, c = INTERNAL_MLKEM_Encaps(ek_bytes, m_bytes, MLKEM768)

                actual_k = K.hex().upper()
                actual_c = c.hex().upper()

                # Live Comparison Logic
                k_status = "PASS"
                c_status = "PASS"
                if tcid in expected_lookup:
                    if actual_k != expected_lookup[tcid].get("k").upper(): k_status = "FAIL"
                    if actual_c != expected_lookup[tcid].get("c").upper(): c_status = "FAIL"

                print(f"{tcid:<6} | {k_status:<17} | {c_status:<17}")

                results["testResults"].append({
                    "tcId": tcid,
                    "c": actual_c,
                    "k": actual_k
                })
    
    # Save the generated results
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"\nDetailed results saved to {OUTPUT_FILE}")

# Execute
verify_mlkem_encap_range(PROMPT_FILE, EXPECTED_FILE)

