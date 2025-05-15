import requests
import json

API_KEY = "5e367f27-3878-4492-9a9e-9eb4bed215e4"

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

params = {
    "resultsPerPage": 1000
}

headers = {
    "apiKey": API_KEY
}

print("[*] Fetching CVE data...")
response = requests.get(url, headers=headers, params=params)

if response.status_code == 200:
    data = response.json()
    with open("cve_data.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print("[+] Saved CVE data to cve_data.json")
else:
    print("[-] Error:", response.status_code)
    print(response.text)
