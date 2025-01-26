# Threat Intelligence Extraction Tool

This project is a Flask-based web application that automates the extraction of key threat intelligence data from natural language threat reports. The tool leverages NLP (Natural Language Processing) and APIs for efficient identification of Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), geolocation of IPs, and enriched malware metadata.

---

## Features
- **IoC Extraction:** Automatically identifies IP addresses, domains, file hashes, email addresses, and URLs from input text.
- **TTP Mapping:** Maps tactics and techniques to the MITRE ATT&CK framework.
- **Threat Actor Identification:** Extracts threat actor names and targeted regions.
- **Malware Enrichment:** Integrates VirusTotal API to enrich IoC data with additional metadata.
- **Geolocation:** Enriches IP addresses with geographic details using the IPGeolocation API.
- **Interactive UI:** Provides an easy-to-use web interface for uploading reports and visualizing results.

---

## Requirements
### System Requirements:
- Python 3.8 or above

### Dependencies:
Install required libraries using:
```bash
pip install -r requirements.txt
```

Dependencies include:
- Flask
- spacy
- requests
- pdfplumber
- python-dotenv

Additionally, download the SpaCy English model:
```bash
python -m spacy download en_core_web_sm
```

---

## How to Set Up and Run

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Heartking-2324/IITK_ps1- // currently private 
   cd IITK_ps1-
   ```


2. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

3. **Run the Application:**
   ```bash
   python theret_intel.py
   ```
   The application will be available at `http://127.0.0.1:5000/`.

---

## How It Works

1. **Upload a Threat Report:**
   - Users can upload a PDF threat report via the web interface.
   ![](https://github.com/Heartking-2324/IITK_ps1-/blob/main/templates/Screenshot%202025-01-27%20003050.png)

2. **Processing:**
   - The tool extracts text from the PDF.
   - Extracts IoCs using regex patterns.
   - Maps TTPs to the MITRE ATT&CK framework.
   - Enriches IPs with geolocation data and file hashes with VirusTotal metadata.

3. **Output:**
   - Displays the extracted data on the web interface in a structured JSON format.
   - Allows filtering of specific data (e.g., only IP addresses).
   ![](https://github.com/Heartking-2324/IITK_ps1-/blob/main/templates/output%20json.jpg)

---

## Key Benefits
- **Efficiency:** Automates manual tasks of extracting and analyzing threat data.
- **Accuracy:** Utilizes APIs and NLP to ensure precise data extraction.
- **User-Friendly:** Simplifies complex reports into actionable intelligence.

---

## File Structure
```
IITK_ps1-
├── app.py                 # Main application script
├── requirements.txt       # Python dependencies
├── templates/
│   ├── index.html         # Home page
│   ├── results.html       # Results page
├── README.md              # Documentation
```

---

## Future Improvements
- Add visualizations for geolocation and IoC statistics.
- Expand TTP mappings and include more comprehensive metadata.

For any issues or contributions, feel free to raise an issue or submit a pull request.
