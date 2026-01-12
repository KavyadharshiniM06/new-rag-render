import os
import time
import json
import requests
from datetime import datetime, timedelta

# ===== CONFIG =====
API_KEY = os.getenv("NVD_API_KEY")  # Your NVD API key
OUTPUT_DIR = "data/cve"
TOP_N = 100  # Number of top CVEs to keep

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Step 1: Delete old CVE files
for file in os.listdir(OUTPUT_DIR):
    if file.endswith(".txt") or file.endswith(".json"):
        os.remove(os.path.join(OUTPUT_DIR, file))
print("[+] Old CVE files deleted")

# Step 2: Define date range (last 30 days)
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=30)
start_iso = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
end_iso = end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
print(f"[+] Fetching CVEs from {start_iso} to {end_iso}")

# Step 3: Fetch CVEs from NVD API
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "pubStartDate": start_iso,
    "pubEndDate": end_iso,
    "startIndex": 0,
    "resultsPerPage": 2000
}
headers = {"Accept": "application/json", "apiKey": API_KEY}

cve_list = []

while True:
    print(f"[+] Requesting batch starting at index {params['startIndex']}...")
    response = requests.get(base_url, headers=headers, params=params)

    if response.status_code != 200:
        print(f"[!] NVD API error {response.status_code}, retrying in 10s...")
        time.sleep(10)
        continue

    try:
        data = response.json()
    except Exception as e:
        print(f"[!] Failed to parse JSON: {e}, retrying in 10s...")
        time.sleep(10)
        continue

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        break

    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # Extract English description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break

        # Extract severity
        severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            sev = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity")
            if sev:
                severity = sev

        # Extract references
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        # Extract affected products
        products = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches:
                    cpe_uri = cpe.get("criteria")
                    if cpe_uri:
                        products.append(cpe_uri)
        if not products:
            products.append("Not specified")

        cve_list.append({
            "cve_id": cve_id,
            "severity": severity,
            "description": desc,
            "affected_products": products,
            "references": refs
        })

    total = data.get("totalResults", 0)
    next_index = params["startIndex"] + params["resultsPerPage"]
    if next_index >= total:
        break
    params["startIndex"] = next_index
    time.sleep(6)  # avoid API rate limits

print(f"[+] Total CVEs fetched: {len(cve_list)}")

# Step 4: Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN)
severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
cve_list.sort(key=lambda x: severity_order.get(x["severity"].upper(), 4))

# Step 5: Keep only top N CVEs
top_cves = cve_list[:TOP_N]

# Step 6: Save JSON
json_dataset = []
for cve in top_cves:
    json_dataset.append({
        "id": cve["cve_id"],
        "severity": cve["severity"],
        "sections": {
            "description": cve["description"],
            "affected_products": cve["affected_products"],
            "references": cve["references"]
        }
    })

json_path = os.path.join(OUTPUT_DIR, "cve_dataset.json")
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(json_dataset, f, indent=2)

print(f"[+] Top {TOP_N} CVEs saved in {json_path}")
