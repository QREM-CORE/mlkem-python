import json
import os
import sys

# Ensure your src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_Decaps

class MLKEM768:
    k = 3
    eta1 = 2
    eta2 = 2
    q = 3329
    n = 256
    du = 10
    dv = 4

# Use the same file for input and expected values
INTERNAL_FILE = 'vectors/ML-KEM-encapDecap-FIPS203/internalProjection.json'
OUTPUT_FILE = 'results/mlkem_768_decap_results.json'

def verify_mlkem_decap_internal(file_path):
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return

    with open(file_path, 'r') as f:
        data = json.load(f)

    results = {
        "vsId": data.get("vsId"),
        "algorithm": data.get("algorithm"),
        "testResults": []
    }

    print(f"{'tcId':<6} | {'Status':<10}")
    print("-" * 20)

    for group in data.get("testGroups", []):
        if group.get("parameterSet") != "ML-KEM-768":
            continue

        for test in group.get("tests", []):
            tcid = test.get("tcId")
            
            # Filter for range 26 to 50
            if 26 <= tcid <= 50:
                # In internalProjection, dk, c, and the expected k are all in the same object
                dk_bytes = bytes.fromhex(test["dk"])
                c_bytes = bytes.fromhex(test["c"])
                expected_k = test["k"].upper()

                try:
                    # Execute Decapsulation
                    actual_k_bytes = INTERNAL_MLKEM_Decaps(dk_bytes, c_bytes, MLKEM768)
                    actual_k = actual_k_bytes.hex().upper()

                    # Compare against the 'k' provided in the same file
                    match = "PASS" if actual_k == expected_k else "FAIL"
                    print(f"{tcid:<6} | {match:<10}")

                    results["testResults"].append({
                        "tcId": tcid,
                        "k": actual_k,
                        "status": match
                    })

                except Exception as e:
                    print(f"{tcid:<6} | ERROR: {str(e)[:15]}")

    # Save results
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"\nResults saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    verify_mlkem_decap_internal(INTERNAL_FILE)