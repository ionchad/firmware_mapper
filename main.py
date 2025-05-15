import analyze
import json

def load_cve_data(filename="cve_data.json"):
    """Load CVE data from a JSON file."""
    with open(filename, "r", encoding="utf-8") as f:
        return json.load(f)

def match_cves(suspicious_keywords, versions, cve_data):
    """
    Simple CVE matcher: 
    Looks for CVEs matching suspicious keywords or component versions.
    """
    matches = []

    for cve_id, details in cve_data.items():
        desc = details.get("description", "").lower()
        tags = details.get("tags", [])
        
        if any(keyword.lower() in desc for keyword in suspicious_keywords):
            matches.append(cve_id)
            continue
        
        # Check if version matches (very simple, exact match)
        component = details.get("component", "").lower()
        version = details.get("version", "")
        if component in versions and versions[component] == version:
            matches.append(cve_id)

    return matches

def main():
    print("[1] Reading firmware.bin...")
    with open("firmware.bin", "rb") as f:
        data = f.read()

    print("[2] Analyzing firmware...")
    suspicious, versions = analyze.analyze_firmware(data)

    print("[3] Loading CVE data...")
    cve_data = load_cve_data()

    print("[4] Matching CVEs...")
    matches = match_cves(suspicious, versions, cve_data)

    print("\nSuspicious services/features found:")
    for s in suspicious:
        print(f" - {s}")

    print("\nDetected component versions:")
    for comp, ver in versions.items():
        print(f" - {comp}: {ver}")

    print("\nMatched CVEs:")
    if matches:
        for cve in matches:
            print(f" - {cve}")
    else:
        print(" No CVEs matched.")

if __name__ == "__main__":
    main()
