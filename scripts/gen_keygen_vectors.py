import json
import os
import sys
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_KeyGen
from mlkem import Internal_kpke
from mlkem import trace_auxiliaries as auxiliaries

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
    Reorganizes the flat ntt_stage_traces list into ROM hardware pass structure.

    Each forward NTT call produces 8 entries:
        [0] stage="input"           raw input before any butterfly
        [1] stage=0, length=128  ┐  ROM 1 Radix-4 pass 1
        [2] stage=1, length=64   ┘
        [3] stage=2, length=32   ┐  ROM 1 Radix-4 pass 2
        [4] stage=3, length=16   ┘
        [5] stage=4, length=8    ┐  ROM 1 Radix-4 pass 3
        [6] stage=5, length=4    ┘
        [7] stage=6, length=2       ROM 2 final Radix-2
    """
    rom_output = []
    num_calls  = len(stage_traces) // 8

    for ntt_index in range(num_calls):
        chunk = stage_traces[ntt_index * 8 : (ntt_index + 1) * 8]

        if len(chunk) != 8:
            print(f"  Warning: ntt_index={ntt_index} incomplete ({len(chunk)}/8 entries). Skipping.")
            continue

        if chunk[0].get("stage") != "input":
            print(f"  Warning: ntt_index={ntt_index} first entry is not 'input'. Skipping.")
            continue

        s = [chunk[i]["coeffs"] for i in range(1, 8)]

        rom_output.append({
            "ntt_index": ntt_index,
            "direction": "forward",
            "input":     chunk[0]["coeffs"],
            "ROM1_R4NTT": {
                "pass_1": {
                    "after_stage_0_length128": s[0],
                    "after_stage_1_length64":  s[1]
                },
                "pass_2": {
                    "after_stage_2_length32":  s[2],
                    "after_stage_3_length16":  s[3]
                },
                "pass_3": {
                    "after_stage_4_length8":   s[4],
                    "after_stage_5_length4":   s[5]
                }
            },
            "ROM2_OMEGA": {
                "final_radix2": {
                    "after_stage_6_length2": s[6]
                }
            }
        })

    return rom_output

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

            # Clear all traces before each test
            Internal_kpke.ntt_traces = []
            auxiliaries.ntt_stage_traces.clear()
            auxiliaries.cbd_traces.clear()

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
                "tcId":              test.get("tcId"),
                "d":                 test.get("d"),
                "z":                 test.get("z"),
                "ek":                ek_bytes.hex().upper(),
                "dk":                dk_bytes.hex().upper(),
                "S_and_E_vectors":   s_and_e,
                "ntt_intermediates": list(Internal_kpke.ntt_traces),
                "rom_passes":        rom_passes
            }
            new_group["tests"].append(test_entry)

            print(f"  tcId={test.get('tcId')} "
                  f"| rom_entries={len(rom_passes)} "
                  f"| S_polys={len(s_and_e['S'])} "
                  f"| E_polys={len(s_and_e['E'])}")

        output_data["testGroups"].append(new_group)

    os.makedirs("results", exist_ok=True)

    output_filename = "results/output_ntt_radix2_results.json"
    with open(output_filename, "w") as f:
        f.write(compact_json_dumps(output_data))
    print(f"\nResults saved to {output_filename}")


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