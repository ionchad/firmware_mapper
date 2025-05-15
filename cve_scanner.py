import json
import re

# Simple keywords to look for in files
SUSPICIOUS_KEYWORDS = [
    "telnet",
    "ssh",
    "dropbear",
    "openssl",
    "openssh",
    "busybox",
    "webadmin",
    "admin",
    "root",
    "login",
    "uClibc",
]

def load_cve_data(cve_path):
    with open(cve_path, "r", encoding="utf-8") as f:
        return json.load(f)

def extract_versions(file_content):
    # Try to grab version strings like OpenSSH_8.2p1 or Dropbear v2017.75
    version_pattern = r"(OpenSSH|Dropbear|BusyBox|uClibc)[^\n]*?(\d+\.\d+[\w\.]*)"
    return re.findall(version_pattern, file_content, flags=re.IGNORECASE)

def match_cves(keywords, versions, cve_data):
    matched = []

    for item in cve_data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")
        description = cve.get("descriptions", [{}])[0].get("value", "").lower()
        severity = "N/A"
        score = 0

        metrics = item.get("cve", {}).get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
            severity = cvss.get("baseSeverity", "N/A")
            score = cvss.get("baseScore", 0)

        for kw in keywords:
            if kw.lower() in description:
                matched.append((cve_id, kw, severity, score, description[:200] + "..."))
                break  # stop at first match

        for product, ver in versions:
            combo = f"{product} {ver}".lower()
            if combo in description:
                matched.append((cve_id, combo, severity, score, description[:200] + "..."))
                break

    return matched
