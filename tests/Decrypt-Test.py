import json
import os
import sys

# Ensure your src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_Encaps, INTERNAL_MLKEM_Decaps

class MLKEM768:
    k = 3
    eta1 = 2
    eta2 = 2
    q = 3329
    n = 256
    du = 10
    dv = 4

def run_internal_projection_test(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    print(f"{'tcId':<6} | {'Encap K':<10} | {'Encap C':<10} | {'Decap K':<10}")
    print("-" * 55)

    results = []

    for group in data.get("testGroups", []):
        # We target ML-KEM-768
        if group.get("parameterSet") != "ML-KEM-768":
            continue

        for test in group.get("tests", []):
            tcid = test.get("tcId")
            
            # Target range 26 to 50
            if 26 <= tcid <= 50:
                # 1. Parse Inputs
                ek_bytes = bytes.fromhex(test["ek"])
                dk_bytes = bytes.fromhex(test["dk"])
                m_bytes = bytes.fromhex(test["m"])
                expected_c = test["c"].upper()
                expected_k = test["k"].upper()

                # 2. Perform Encapsulation (Generates actual_k and actual_c)
                # Note: m is the randomness seed provided in the test vector
                actual_encap_k, actual_encap_c = INTERNAL_MLKEM_Encaps(ek_bytes, m_bytes, MLKEM768)
                
                # 3. Perform Decapsulation (Uses c from the file to derive actual_decap_k)
                # This tests the ability to recover the key from the provided ciphertext
                actual_decap_k = INTERNAL_MLKEM_Decaps(bytes.fromhex(expected_c), dk_bytes, MLKEM768)

                # 4. Compare
                encap_k_match = "PASS" if actual_encap_k.hex().upper() == expected_k else "FAIL"
                encap_c_match = "PASS" if actual_encap_c.hex().upper() == expected_c else "FAIL"
                decap_k_match = "PASS" if actual_decap_k.hex().upper() == expected_k else "FAIL"

                print(f"{tcid:<6} | {encap_k_match:<10} | {encap_c_match:<10} | {decap_k_match:<10}")

                results.append({
                    "tcId": tcid,
                    "encap_status": {"k": encap_k_match, "c": encap_c_match},
                    "decap_status": {"k": decap_k_match}
                })

    return results

# Execute the test
# Replace with the actual path to your internalProjection.json
run_internal_projection_test('tests/ML-KEM-encapDecap-FIPS203/internalProjection.json')