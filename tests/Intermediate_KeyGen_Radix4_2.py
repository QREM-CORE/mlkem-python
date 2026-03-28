import json
import os
import sys
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_KeyGen
from mlkem import Internal_kpke
from mlkem import auxiliaries

class MLKEM768:
    k    = 3
    eta1 = 2
    eta2 = 2
    q    = 3329
    n    = 256
    du   = 10
    dv   = 4

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

def organize_rom_passes(stage_traces):
    """
    Reorganizes ntt_stage_traces into ROM hardware pass structure.

    Each Radix-4/2 NTT call produces 5 entries:
        [0] stage="input"       raw polynomial before any butterfly
        [1] stage="r4_pass_1"   after ROM1 Radix-4 pass 1 (stride=64)
        [2] stage="r4_pass_2"   after ROM1 Radix-4 pass 2 (stride=16)
        [3] stage="r4_pass_3"   after ROM1 Radix-4 pass 3 (stride=4)
        [4] stage="r2_final"    after ROM2 final Radix-2  (stride=2)
    """
    rom_output = []
    num_calls  = len(stage_traces) // 5

    for ntt_index in range(num_calls):
        chunk = stage_traces[ntt_index * 5 : (ntt_index + 1) * 5]

        if len(chunk) != 5:
            print(f"  Warning: ntt_index={ntt_index} incomplete ({len(chunk)}/5 entries). Skipping.")
            continue

        if chunk[0].get("stage") != "input":
            print(f"  Warning: ntt_index={ntt_index} first entry is not 'input'. Skipping.")
            continue

        rom_output.append({
            "ntt_index": ntt_index,
            "direction": "forward",
            "input":     chunk[0]["coeffs"],
            "ROM1_R4NTT": {
                "pass_1": chunk[1]["coeffs"],
                "pass_2": chunk[2]["coeffs"],
                "pass_3": chunk[3]["coeffs"]
            },
            "ROM2_OMEGA": {
                "final_radix2": chunk[4]["coeffs"]
            }
        })

    return rom_output

# =============================================================================
# === Separate Output Writers
# =============================================================================

def save_multiply_ntt(output_data):
    """
    Collects all MultiplyNTTs call traces per test and writes them to
    results/multiply_ntt_results.json.
    """
    multiply_ntt_output = {
        "vsId":       output_data.get("vsId"),
        "algorithm":  output_data.get("algorithm"),
        "revision":   output_data.get("revision"),
        "testGroups": []
    }

    for group in output_data.get("testGroups", []):
        new_group = {
            "tgId":         group.get("tgId"),
            "parameterSet": group.get("parameterSet"),
            "tests":        []
        }

        for test in group.get("tests", []):
            new_group["tests"].append({
                "tcId":               test.get("tcId"),
                "d":                  test.get("d"),
                "z":                  test.get("z"),
                "multiply_ntt_calls": test.get("multiply_ntt_traces", [])
            })

        multiply_ntt_output["testGroups"].append(new_group)

    os.makedirs("results", exist_ok=True)
    filename = "results/multiply_ntt_results.json"
    with open(filename, "w") as f:
        f.write(compact_json_dumps(multiply_ntt_output))
    print(f"MultiplyNTT results saved to    {filename}")


# =============================================================================
# === Main
# =============================================================================

def verify_and_capture(data):
    output_data = {
        "vsId":       data.get("vsId"),
        "algorithm":  data.get("algorithm"),
        "revision":   data.get("revision"),
        "testGroups": []
    }

    for group in data.get("testGroups", []):
        if group.get("parameterSet") != "ML-KEM-768":
            continue

        new_group = {
            "tgId":         group.get("tgId"),
            "parameterSet": group.get("parameterSet"),
            "tests":        []
        }

        for test in group.get("tests", []):

            # Clear ALL traces before each test for full isolation
            Internal_kpke.ntt_traces = []
            auxiliaries.ntt_stage_traces.clear()
            auxiliaries.cbd_traces.clear()
            auxiliaries.multiply_ntt_traces.clear()
            auxiliaries.compress_traces.clear()
            auxiliaries.decompress_traces.clear()

            d_bytes = bytes.fromhex(test.get("d"))
            z_bytes = bytes.fromhex(test.get("z"))

            # Run KeyGen — populates all trace lists as a side effect
            ek_bytes, dk_bytes = INTERNAL_MLKEM_KeyGen(d_bytes, z_bytes, MLKEM768)

            # Extract S and E vectors from CBD traces
            # For ML-KEM-768 (k=3):
            #   cbd_traces[0..2] = S vector (secret)
            #   cbd_traces[3..5] = E vector (error)
            k   = MLKEM768.k
            cbd = list(auxiliaries.cbd_traces)
            s_and_e = {
                "S": [cbd[i]["coeffs"] for i in range(k)      if i < len(cbd)],
                "E": [cbd[i]["coeffs"] for i in range(k, 2*k) if i < len(cbd)]
            }

            rom_passes = organize_rom_passes(list(auxiliaries.ntt_stage_traces))

            test_entry = {
                "tcId":                test.get("tcId"),
                "d":                   test.get("d"),
                "z":                   test.get("z"),
                "ek":                  ek_bytes.hex().upper(),
                "dk":                  dk_bytes.hex().upper(),
                "S_and_E_vectors":     s_and_e,
                "ntt_intermediates":   list(Internal_kpke.ntt_traces),
                "rom_passes":          rom_passes,
                "multiply_ntt_traces": list(auxiliaries.multiply_ntt_traces),
            
            }
            new_group["tests"].append(test_entry)

            print(f"  tcId={test.get('tcId')} "
                  f"| rom_entries={len(rom_passes)} "
                  f"| S_polys={len(s_and_e['S'])} "
                  f"| E_polys={len(s_and_e['E'])} "
                  f"| multiply_ntt_calls={len(auxiliaries.multiply_ntt_traces)} "
                  )

        output_data["testGroups"].append(new_group)

    os.makedirs("results", exist_ok=True)

    # --- Primary output ---
    output_filename = "results/output_ntt_radix_4_2.json"
    with open(output_filename, "w") as f:
        f.write(compact_json_dumps(output_data))
    print(f"\nMain results saved to        {output_filename}")

    # --- Separate focused outputs ---
    save_multiply_ntt(output_data)
   


# =============================================================================
# === Entry Point
# =============================================================================

input_path = "ML-KEM-KeyGen-FIPS203/prompt (1).json"
if os.path.exists(input_path):
    with open(input_path, "r") as f:
        input_data = json.load(f)
    verify_and_capture(input_data)
else:
    print(f"Error: Could not find {input_path}")