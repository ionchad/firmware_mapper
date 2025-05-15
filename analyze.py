# analyze.py

def analyze_firmware(data):
    """
    Analyzes firmware binary data.
    Returns:
      - suspicious: a list of suspicious strings or features found
      - versions: a dict of detected component versions (for CVE matching)
    """
    suspicious = []
    versions = {}

    # Convert binary data to string for simple scanning
    try:
        text = data.decode(errors='ignore')
    except Exception:
        text = ""

    # Example: look for suspicious keywords
    keywords = {
        "dropbear": "Dropbear SSH service",
        "telnetd": "Telnet service",
        "mini_httpd": "Mini HTTPD web server",
        "busybox": "BusyBox utilities",
        "ssh": "SSH service",
    }

    for key, desc in keywords.items():
        if key in text:
            suspicious.append(desc)

    # Example: find versions (simple heuristic)
    import re
    # Look for version strings like "BusyBox v1.31.1"
    busybox_ver = re.search(r"BusyBox v?(\d+\.\d+(\.\d+)*)", text)
    if busybox_ver:
        versions['busybox'] = busybox_ver.group(1)

    dropbear_ver = re.search(r"dropbear v?(\d+\.\d+(\.\d+)*)", text, re.IGNORECASE)
    if dropbear_ver:
        versions['dropbear'] = dropbear_ver.group(1)

    # Return collected data
    return suspicious, versions
