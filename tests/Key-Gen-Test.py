import json
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from mlkem.internal_mlkem import INTERNAL_MLKEM_KeyGen
class MLKEM768:
    k = 3
    eta1 = 2
    eta2 = 2
    q = 3329  # Constant for all ML-KEM sets
    n = 256
    du = 10
    dv = 4


# Load your provided JSON file
with open('tests/ML-KEM-KeyGen-FIPS203/prompt (1).json', 'r') as f:
    input_data = json.load(f)

def verify_mlkem_vectors(data):
    results = {
        "vsId": data.get("vsId"),
        "algorithm": data.get("algorithm"),
        "testResults": []
    }

    for group in data.get("testGroups", []):
        param_set = group.get("parameterSet")
        
        # Only process ML-KEM-768
        if param_set != "ML-KEM-768":
            continue

        for test in group.get("tests", []):
            tcid = test.get("tcId")
            d_bytes = bytes.fromhex(test.get("d"))
            z_bytes = bytes.fromhex(test.get("z"))

            # Run the key generation
            ek_bytes, dk_bytes = INTERNAL_MLKEM_KeyGen(d_bytes, z_bytes, MLKEM768)

            # Convert to Uppercase Hex
            actual_dk = dk_bytes.hex().upper()
            actual_ek = ek_bytes.hex().upper()

            # Store results (omitting comparison since 'dk'/'ek' are missing from your JSON)
            results["testResults"].append({
                "tcId": tcid,
                "ek": actual_ek,
                "dk": actual_dk
            })
    
    # Write the results to a file so they are actually generated
    with open('tests/results/mlkem_768_results.json', 'w') as f:
        import json
        json.dump(results, f, indent=4)
    
    print("Results generated to mlkem_768_results.json")
# Run the verification
verify_mlkem_vectors(input_data)