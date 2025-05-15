# Firmware Attack Surface Mapper

This tool extracts and analyzes firmware binaries to find suspicious services and known vulnerabilities, cves.

## How to use

1. Place your firmware `.bin` file in the project folder. Must be named "firmware"
2. Make sure you have Python 3 installed.
3. If you wanna download cves run python download_cves.py but you need to get an API key at https://nvd.nist.gov/developers/request-an-api-key and modify the code on the python file with your API key.
4. Run the tool:

   ```bash
   python main.py
