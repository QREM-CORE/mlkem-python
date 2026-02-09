import json
import os
import sys
import re

# Ensure your src directory is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_KeyGen
from mlkem import Internal_kpke

class MLKEM768:
    k = 3
    eta1 = 2
    eta2 = 2
    q = 3329
    n = 256
    du = 10
    dv = 4

def compact_json_dumps(obj):
    """
    Tricks the JSON string to put integer arrays on a single line 
    while keeping the rest of the structure indented.
    """
    # Generate the standard indented JSON
    res = json.dumps(obj, indent=2)

    return re.sub(
        r'\[\s+((?:-?\d+,\s+)*-?\d+)\s+\]', 
        lambda m: '[' + re.sub(r'\s+', ' ', m.group(1)) + ']', 
        res
    )

def verify_and_capture(data):
    output_data = {
        "vsId": data.get("vsId"),
        "algorithm": data.get("algorithm"),
        "revision": data.get("revision"),
        "testGroups": []
    }

    for group in data.get("testGroups", []):
        # Filter for ML-KEM-768
        if group.get("parameterSet") != "ML-KEM-768":
            continue

        new_group = {
            "tgId": group.get("tgId"),
            "parameterSet": group.get("parameterSet"),
            "tests": []
        }
        
        for test in group.get("tests", []):
            # 1. Clear previous intermediates to ensure isolation
            Internal_kpke.ntt_traces = []
            
            d_bytes = bytes.fromhex(test.get("d"))
            z_bytes = bytes.fromhex(test.get("z"))

            # 2. Run KeyGen (Internal calls will populate auxiliaries.ntt_traces)
            ek_bytes, dk_bytes = INTERNAL_MLKEM_KeyGen(d_bytes, z_bytes, MLKEM768)

            # 3. Build the test result object with a SNAPSHOT of the traces
            test_entry = {
                "tcId": test.get("tcId"),
                "d": test.get("d"), # including inputs to match prompt format
                "z": test.get("z"),
                "ek": ek_bytes.hex().upper(),
                "dk": dk_bytes.hex().upper(),
                "ntt_intermediates": list(Internal_kpke.ntt_traces)
            }
            new_group["tests"].append(test_entry)
            
        output_data["testGroups"].append(new_group)

    # 4. Save to JSON using the compact formatter
    output_filename = 'tests/results/output_ntt_results.json'
    with open(output_filename, 'w') as f:
        f.write(compact_json_dumps(output_data))
    
    print(f"Results saved to {output_filename}")

# Load prompt.json and run
input_path = 'tests/ML-KEM-KeyGen-FIPS203/prompt (1).json'
if os.path.exists(input_path):
    with open(input_path, 'r') as f:
        input_data = json.load(f)
    verify_and_capture(input_data)
else:
    print(f"Error: Could not find {input_path}")