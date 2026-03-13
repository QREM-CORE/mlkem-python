import json
import os
import sys
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from mlkem.internal_mlkem import INTERNAL_MLKEM_KeyGen
from mlkem import Internal_kpke
from mlkem import auxiliaries

class MLKEM768:
    k = 3
    eta1 = 2
    eta2 = 2
    q = 3329
    n = 256
    du = 10
    dv = 4

def compact_json_dumps(obj):
    res = json.dumps(obj, indent=2)
    return re.sub(
        r'\[\s+((?:-?\d+,\s+)*-?\d+)\s+\]',
        lambda m: '[' + re.sub(r'\s+', ' ', m.group(1)) + ']',
        res
    )

def organize_rom_passes(stage_traces):
    """
    Takes a flat list of 7-stage NTT snapshots (one entry per NTT call)
    and reorganizes them into ROM 1/2/3/4 hardware pass structure.

    Expected format of each entry in stage_traces:
        {
            "direction": "forward" | "inverse",
            "ntt_index": int,          # which NTT call this was
            "stages": [s0, s1, ..., s6]  # 7 polynomial snapshots
        }

    Forward NTT stages map to:
        ROM 1 Radix-4 Pass 1 : stages[0] (length=128), stages[1] (length=64)
        ROM 1 Radix-4 Pass 2 : stages[2] (length=32),  stages[3] (length=16)
        ROM 1 Radix-4 Pass 3 : stages[4] (length=8),   stages[5] (length=4)
        ROM 2 Radix-2        : stages[6] (length=2)

    Inverse NTT stages map to:
        ROM 4 Radix-2        : stages[0] (length=2)
        ROM 3 Radix-4 Pass 1 : stages[1] (length=4),   stages[2] (length=8)
        ROM 3 Radix-4 Pass 2 : stages[3] (length=16),  stages[4] (length=32)
        ROM 3 Radix-4 Pass 3 : stages[5] (length=64),  stages[6] (length=128)
    """
    rom_output = []

    for entry in stage_traces:
        direction = entry.get("direction")
        ntt_index = entry.get("ntt_index")
        stages    = entry.get("stages", [])

        if len(stages) != 7:
            print(f"  Warning: ntt_index={ntt_index} has {len(stages)} stages, expected 7. Skipping.")
            continue

        if direction == "forward":
            rom_entry = {
                "ntt_index": ntt_index,
                "direction": "forward",
                "ROM1_R4NTT": {
                    "pass_1": {
                        "after_stage_1_length128": stages[0],
                        "after_stage_2_length64":  stages[1]
                    },
                    "pass_2": {
                        "after_stage_3_length32":  stages[2],
                        "after_stage_4_length16":  stages[3]
                    },
                    "pass_3": {
                        "after_stage_5_length8":   stages[4],
                        "after_stage_6_length4":   stages[5]
                    }
                },
                "ROM2_OMEGA": {
                    "final_radix2": {
                        "after_stage_7_length2":   stages[6]
                    }
                }
            }

        elif direction == "inverse":
            rom_entry = {
                "ntt_index": ntt_index,
                "direction": "inverse",
                "ROM4_OMEGA_INV": {
                    "initial_radix2": {
                        "after_stage_1_length2":   stages[0]
                    }
                },
                "ROM3_R4INTT": {
                    "pass_1": {
                        "after_stage_2_length4":   stages[1],
                        "after_stage_3_length8":   stages[2]
                    },
                    "pass_2": {
                        "after_stage_4_length16":  stages[3],
                        "after_stage_5_length32":  stages[4]
                    },
                    "pass_3": {
                        "after_stage_6_length64":  stages[5],
                        "after_stage_7_length128": stages[6]
                    }
                }
            }

        else:
            print(f"  Warning: unknown direction '{direction}' for ntt_index={ntt_index}. Skipping.")
            continue

        rom_output.append(rom_entry)

    return rom_output


def verify_and_capture(data):
    output_data = {
        "vsId":       data.get("vsId"),
        "algorithm":  data.get("algorithm"),
        "revision":   data.get("revision"),
        "testGroups": []
    }

    stage_output = {
        "vsId":       data.get("vsId"),
        "algorithm":  data.get("algorithm"),
        "revision":   data.get("revision"),
        "testGroups": []
    }

    rom_output = {
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
        stage_group = {
            "tgId":         group.get("tgId"),
            "parameterSet": group.get("parameterSet"),
            "tests":        []
        }
        rom_group = {
            "tgId":         group.get("tgId"),
            "parameterSet": group.get("parameterSet"),
            "tests":        []
        }

        for test in group.get("tests", []):
            Internal_kpke.ntt_traces = []
            auxiliaries.ntt_stage_traces.clear()

            d_bytes = bytes.fromhex(test.get("d"))
            z_bytes = bytes.fromhex(test.get("z"))

            ek_bytes, dk_bytes = INTERNAL_MLKEM_KeyGen(d_bytes, z_bytes, MLKEM768)

            # Main results
            test_entry = {
                "tcId": test.get("tcId"),
                "d":    test.get("d"),
                "z":    test.get("z"),
                "ek":   ek_bytes.hex().upper(),
                "dk":   dk_bytes.hex().upper(),
                "ntt_intermediates": list(Internal_kpke.ntt_traces)
            }
            new_group["tests"].append(test_entry)

            # Raw stage snapshots
            stage_entry = {
                "tcId":             test.get("tcId"),
                "ntt_stage_traces": list(auxiliaries.ntt_stage_traces)
            }
            stage_group["tests"].append(stage_entry)

            # ROM-organized passes  <-- new
            rom_entry = {
                "tcId":      test.get("tcId"),
                "rom_passes": organize_rom_passes(list(auxiliaries.ntt_stage_traces))
            }
            rom_group["tests"].append(rom_entry)

            print(f"  tcId={test.get('tcId')} | stages={len(auxiliaries.ntt_stage_traces)} "
                  f"| rom_entries={len(rom_entry['rom_passes'])}")

        output_data["testGroups"].append(new_group)
        stage_output["testGroups"].append(stage_group)
        rom_output["testGroups"].append(rom_group)

    os.makedirs("tests/results", exist_ok=True)

    output_filename = "tests/results/output_ntt_results.json"
    with open(output_filename, "w") as f:
        f.write(compact_json_dumps(output_data))
    print(f"\nMain results saved to      {output_filename}")

    stage_filename = "tests/results/output_ntt_stages.json"
    with open(stage_filename, "w") as f:
        f.write(compact_json_dumps(stage_output))
    print(f"Stage snapshots saved to   {stage_filename}")

    rom_filename = "tests/results/output_ntt_roms.json"
    with open(rom_filename, "w") as f:
        f.write(compact_json_dumps(rom_output))
    print(f"ROM pass output saved to   {rom_filename}")


input_path = "ML-KEM-KeyGen-FIPS203/prompt (1).json"
if os.path.exists(input_path):
    with open(input_path, "r") as f:
        input_data = json.load(f)
    verify_and_capture(input_data)
else:
    print(f"Error: Could not find {input_path}")