# Threat Intelligence Extraction Tool

## Overview
This tool extracts key threat intelligence information from natural language threat reports. It uses Natural Language Processing (NLP) to analyze reports and identify the following:

1. **Indicators of Compromise (IoCs):** Malicious IP addresses, domains, file hashes, or email addresses.
2. **Tactics, Techniques, and Procedures (TTPs):** Mapped to the MITRE ATT&CK framework.
3. **Threat Actors:** Names of threat actor groups or individuals.
4. **Malware Metadata:** Enriched details from VirusTotal.
5. **Targeted Entities:** Organizations, regions, or industries targeted in the attack.

## Features
- Extracts IoCs, including IPs, domains, file hashes, email addresses, and URLs.
- Enriches file hash data using the VirusTotal API.
- Identifies tactics and techniques from the MITRE ATT&CK framework.
- Extracts threat actors and targeted entities using NLP.
- Processes PDF threat reports and outputs structured JSON data.

## Installation

### Prerequisites
- Python 3.8+
- pip

### Steps
1. Clone this repository:
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```
2. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```
3. Set up your environment variables:
   - Create a `.env` file in the root directory.
   - Add the following keys:
     ```plaintext
     VIRUSTOTAL_API_KEY=your_virustotal_api_key
     ```

## Usage
1. Start the Flask server:
    ```bash
    python app.py
    ```
2. Open the web interface in your browser at `http://127.0.0.1:5000`.
3. Upload a PDF threat report to extract intelligence.
4. View or download the JSON output with extracted data.

### Example Input
```plaintext
The APT33 group, suspected to be from Iran, has launched a new campaign targeting
energy sector organizations. The attack utilizes Shamoon malware, known for its destructive capabilities.
```

### Example Output
```json
{
  "IoCs": {
    "IP addresses": ["192.168.1.1"],
    "Domains": ["example.com"],
    "File Hashes": ["abcd1234efgh5678ijkl9012mnop3456"],
    "Email Addresses": ["attacker@example.com"],
    "URLs": ["http://malicious.com"]
  },
  "TTPs": {
    "Tactics": [["TA0001", "Initial Access"]],
    "Techniques": [["T1566.001", "Spear Phishing Attachment"]]
  },
  "Threat Actor(s)": ["APT33"],
  "Targeted Entities": ["Energy Sector"],
  "Threat Score": 85
}
```

## File Structure
```
.
├── app.py                # Main application script
├── requirements.txt      # Required Python dependencies
├── README.md             # Documentation
├── templates/            # HTML templates for the web interface
├── .env                  # Environment variables (not included in the repo)
```

## Dependencies
See `requirements.txt` for a full list of dependencies.

## Limitations
- The tool relies on the quality of PDF text extraction. Poorly formatted PDFs may result in incomplete data.
- Requires a valid VirusTotal API key for file hash enrichment.

## Contribution
Feel free to submit issues or pull requests to improve this tool.

## License
This project is licensed under the MIT License.
