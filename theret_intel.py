import re
import json
import spacy
from flask import Flask, request, jsonify, render_template
import requests
from dotenv import load_dotenv
import os
import pdfplumber

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Load spaCy model
nlp = spacy.load("en_core_web_sm")

# VirusTotal API setup
VIRUSTOTAL_API_KEY = os.getenv("53b2883006ac7fda272011c661f3c0a67cc64b4ee30cc9a26e0892a0e37a9eb7")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/"

# Geolocation API setup
IPGEOLOCATION_API_KEY = os.getenv("IPGEOLOCATION_API_KEY")
IPGEOLOCATION_URL = "https://api.ipgeolocation.io/ipgeo"

# IoC Patterns
IOC_PATTERNS = {
    "IP addresses": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}\b",
    "Domains": r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "File Hashes": r"\b[a-fA-F0-9]{32,64}\b",
    "Email Addresses": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "URLs": r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[a-zA-Z0-9._%+-]*)?",
}

# MITRE ATT&CK Mapping
MITRE_ATTACK_MAPPING = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Exfiltration": "TA0010",
    "Command and Control": "TA0011",
}

# Extract IoCs
def extract_iocs(text):
    iocs = {key: list(set(re.findall(pattern, text))) for key, pattern in IOC_PATTERNS.items()}
    return iocs

# Enrich IPs with Geolocation API
def enrich_with_geolocation(ip_addresses):
    geo_details = []
    for ip in ip_addresses:
        try:
            response = requests.get(
                f"{IPGEOLOCATION_URL}?apiKey={IPGEOLOCATION_API_KEY}&ip={ip}"
            )
            if response.status_code == 200:
                geo_details.append(response.json())
        except Exception as e:
            print(f"Error fetching geolocation for IP {ip}: {e}")
    return geo_details

# Enrich IoCs with VirusTotal API
def enrich_iocs(iocs):
    enriched_data = {"Malware Metadata": []}
    for file_hash in iocs.get("File Hashes", []):
        try:
            response = requests.get(
                f"{VIRUSTOTAL_URL}{file_hash}",
                headers={"x-apikey": VIRUSTOTAL_API_KEY}
            )
            if response.status_code == 200:
                data = response.json()
                enriched_data["Malware Metadata"].append({
                    "hash": file_hash,
                    "ssdeep": data.get("data", {}).get("attributes", {}).get("ssdeep", ""),
                    "TLSH": data.get("data", {}).get("attributes", {}).get("tlsh", ""),
                    "tags": data.get("data", {}).get("attributes", {}).get("tags", [])
                })
        except Exception as e:
            print(f"Error enriching IoC {file_hash}: {e}")
    return enriched_data

# Extract TTPs
def extract_ttps(text):
    doc = nlp(text)
    tactics = []
    techniques = []
    for sentence in doc.sents:
        for tactic, tactic_id in MITRE_ATTACK_MAPPING.items():
            if tactic.lower() in sentence.text.lower():
                tactics.append((tactic_id, tactic))
                if "phishing" in sentence.text.lower():
                    techniques.append(("T1566.001", "Spear Phishing Attachment"))
    return {"Tactics": list(set(tactics)), "Techniques": list(set(techniques))}

# Extract entities (threat actors, targeted regions)
def extract_entities(text):
    doc = nlp(text)
    threat_actors = list(set([ent.text for ent in doc.ents if ent.label_ == "ORG"]))
    targeted_regions = list(set([ent.text for ent in doc.ents if ent.label_ in ["GPE", "LOC"]]))
    return threat_actors, targeted_regions

# Main extraction function
def extract_threat_intelligence(report_text):
    iocs = extract_iocs(report_text)
    ip_geo_details = enrich_with_geolocation(iocs["IP addresses"])
    enriched_iocs = enrich_iocs(iocs)
    ttps = extract_ttps(report_text)
    threat_actors, targeted_regions = extract_entities(report_text)

    threat_score = len(iocs.get("IP addresses", [])) * 10 + len(ttps["Tactics"]) * 5
    threat_score = min(threat_score, 100)

    return {
        "IoCs": iocs,
        "Geo Details": ip_geo_details,
        "TTPs": ttps,
        "Threat Actor(s)": threat_actors,
        "Targeted Entities": targeted_regions,
        "Threat Score": threat_score,
        **enriched_iocs
    }

@app.route("/")
def home():
    return render_template("index.html")  # Flask will look for this file in the templates folder

@app.route("/extract", methods=["POST"])
def extract():
    file = request.files.get("file", None)
    if not file:
        return jsonify({"error": "No file provided."}), 400

    # Extract text from PDF
    try:
        with pdfplumber.open(file) as pdf:
            text = " ".join(page.extract_text() or "" for page in pdf.pages)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Process threat intelligence
    try:
        threat_data = extract_threat_intelligence(text)
        return jsonify(threat_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
