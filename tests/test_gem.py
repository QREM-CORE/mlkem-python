import json

def compare_results(my_results_path, expected_results_path):
    # Load your generated results
    with open(my_results_path, 'r') as f:
        my_data = json.load(f)
    
    # Load the official expected results
    with open(expected_results_path, 'r') as f:
        expected_data = json.load(f)

    # Extract your results into a dictionary for easy lookup
    my_lookup = {t['tcId']: t for t in my_data.get("testResults", [])}

    print(f"{'tcId':<6} | {'EK Result':<10} | {'DK Result':<10} | {'Notes'}")
    print("-" * 55)

    # Official JSONs usually nest tests inside testGroups
    for group in expected_data.get("testGroups", []):
        for test in group.get("tests", []):
            tcid = test.get("tcId")
            
            # Filter for tcId 26 to 50
            if 26 <= tcid <= 50:
                expected_ek = test.get("ek").upper()
                expected_dk = test.get("dk").upper()
                
                actual = my_lookup.get(tcid)
                
                if not actual:
                    print(f"{tcid:<6} | MISSING    | MISSING    | Test not found in output")
                    continue

                actual_ek = actual.get("ek").upper()
                actual_dk = actual.get("dk").upper()

                ek_status = "PASS" if actual_ek == expected_ek else "FAIL"
                dk_status = "PASS" if actual_dk == expected_dk else "FAIL"
                
                note = ""
                if dk_status == "FAIL":
                    # Check if the length is the problem (DK should be 4800 hex chars for ML-KEM-768)
                    if len(actual_dk) != len(expected_dk):
                        note = f"DK Length mismatch (Got {len(actual_dk)}, Exp {len(expected_dk)})"

                print(f"{tcid:<6} | {ek_status:<10} | {dk_status:<10} | {note}")

# Run the comparison
compare_results('tests/results/mlkem_768_results.json', 'tests/ML-KEM-KeyGen-FIPS203/expectedResults.json')