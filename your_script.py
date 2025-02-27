import fitz  # PyMuPDF
import requests
from transformers import pipeline

# === Configuration ===
VIRUSTOTAL_API_KEY = "c0085673951c8e284fccda4e42ef6165e732ba9d0e30848ce1ef19e99d4e8732"  # Get a free API key from virustotal.com
pdf_path = "/Users/sudarshan/resume_security_pipeline/uploads/Sudarshan_Resume copy.pdf"

# === Step 1: Extract Text from PDF ===
def extract_text_from_pdf(pdf_path):
    text = ""
    try:
        doc = fitz.open(pdf_path)
        for page in doc:
            text += page.get_text("text") + "\n"
        return text.strip()
    except Exception as e:
        return f"⚠️ Error extracting text: {e}"

# === Step 2: Scan for Malware with VirusTotal ===
def scan_pdf_for_malware(pdf_path):
    try:
        with open(pdf_path, "rb") as f:
            files = {"file": (pdf_path, f)}
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
        
        result = response.json()
        return result.get("data", {}).get("attributes", {}).get("last_analysis_stats", "No scan results")
    except Exception as e:
        return f"⚠️ Error scanning for malware: {e}"

# === Step 3: Scan Text for PII, Bias, Toxicity ===
def analyze_text(text):
    # Token limit for Hugging Face models
    MAX_TOKENS = 512  

    # Load NLP models
    pii_detector = pipeline("ner", model="obi/deid_roberta_i2b2")
    bias_detector = pipeline("text-classification", model="unitary/unbiased-toxic-roberta")
    toxicity_detector = pipeline("text-classification", model="unitary/toxic-bert")

    # Truncate long text (only take first 512 tokens)
    truncated_text = text[:MAX_TOKENS]

    results = {
        "pii": pii_detector(truncated_text),
        "bias": bias_detector(truncated_text),
        "toxicity": toxicity_detector(truncated_text)
    }
    return results


# === Run the Scanning Process ===
print(f"🔍 Scanning {pdf_path}...\n")
resume_text = extract_text_from_pdf(pdf_path)
malware_scan_result = scan_pdf_for_malware(pdf_path)
analysis_results = analyze_text(resume_text)

# === Display Results ===
print("\n✅ Malware Scan Result:", malware_scan_result)
print("\n📌 Extracted Text Preview:\n", resume_text[:500] + "..." if len(resume_text) > 500 else resume_text)
print("\n🔍 PII Detected:", analysis_results["pii"])
print("\n🧐 Bias Analysis:", analysis_results["bias"])
print("\n☢️ Toxicity Analysis:", analysis_results["toxicity"])
