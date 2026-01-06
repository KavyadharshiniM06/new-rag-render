import os
import time
import requests
from datetime import datetime, timedelta
import json

# ===== CONFIG =====
API_KEY = os.getenv("NVD_API_KEY")  # your NVD API key
OUTPUT_DIR = "data/cve"             # folder to store CVE files
TOP_N = 50                           # number of CVEs to keep

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Step 1: Delete all existing CVE files
for file in os.listdir(OUTPUT_DIR):
    if file.endswith(".txt"):
        os.remove(os.path.join(OUTPUT_DIR, file))
print("[+] Existing CVE files deleted")

# Step 2: Define date range (last 2 months)
end_date = datetime.utcnow()
start_date = end_date - timedelta(days=60)
start_iso = start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
end_iso   = end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")

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
def generate_attack_scenario(description):
    desc = description.lower()

    if "deserialization" in desc or "object injection" in desc:
        return "An attacker can send malicious serialized objects, potentially leading to remote code execution."
    if "remote code execution" in desc or "rce" in desc:
        return "An attacker can execute arbitrary commands on the affected system."
    if "sql" in desc:
        return "An attacker can inject malicious SQL queries to access or manipulate the database."
    if "xss" in desc or "cross-site scripting" in desc:
        return "An attacker can inject malicious scripts that execute in a victim’s browser."
    if "authentication" in desc or "authorization" in desc:
        return "An attacker can bypass authentication or gain unauthorized access."
    if "file upload" in desc or "path traversal" in desc:
        return "An attacker can upload or access unauthorized files on the server."

    return "An attacker can exploit the vulnerability by sending crafted requests to the affected application."

while True:
    print(f"[+] Requesting batch starting at index {params['startIndex']}...")
    response = requests.get(base_url, headers=headers, params=params)
    data = response.json()

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        break

    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # Extract description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break

        # Extract severity
        metrics = cve.get("metrics", {})
        severity = "UNKNOWN"
        if "cvssMetricV31" in metrics:
            sev = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity")
            if sev:
                severity = sev

        #Extract Attack Scenario
        attack_scenario = generate_attack_scenario(desc)
        
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

        # Extract mitigation/patch info from references if available
        mitigation = []
        for ref in refs:
            if "patch" in ref.lower() or "update" in ref.lower():
                mitigation.append(ref)
        if not mitigation:
            mitigation.append("Not specified")

        cve_list.append({
            "cve_id": cve_id,
            "severity": severity,
            "description": desc,
            "attack_scenario": attack_scenario,
            "references": refs,
            "products": products,
            "mitigation": mitigation
        })

    total = data.get("totalResults", 0)
    next_index = params["startIndex"] + params["resultsPerPage"]
    if next_index >= total:
        break
    params["startIndex"] = next_index
    time.sleep(6)

print(f"[+] Total CVEs fetched: {len(cve_list)}")

# Step 4: Sort by severity (Critical > High > Medium > Low > UNKNOWN)
severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
cve_list.sort(key=lambda x: severity_order.get(x["severity"].upper(), 4))

# Step 5: Keep only top N CVEs
top_cves = cve_list[:TOP_N]

json_dataset=[]
for cve in top_cves:
    json_dataset.append({
        "id":cve["cve_id"],
        "severity":cve["severity"],
        "sections":{
            "description":cve["description"],
            "Attack Scenario": cve["attack_scenario"],
            "Affected Products": cve["products"],
            "Mitigation": cve["mitigation"],
            "References": cve["references"]
        }
    })
os.makedirs("data", exist_ok=True)

json_path="data/cve_dataset.json"
with open(json_path, "w", encoding="utf-8") as f:
    json.dump(json_dataset, f, indent=2)
print(f"[+] Top {TOP_N} CVEs with products and mitigation saved in {OUTPUT_DIR}")

