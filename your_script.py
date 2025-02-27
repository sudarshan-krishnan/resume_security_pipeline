import fitz  # PyMuPDF for PDF processing
import requests  # For VirusTotal API
from transformers import pipeline  # NLP models
import pytesseract  # OCR for scanned PDFs
from pdf2image import convert_from_path  # Convert PDFs to images for OCR
import re

# === Configuration ===
VIRUSTOTAL_API_KEY = "your-api-key-here"  # Replace with your VirusTotal API key
pdf_path = "/Users/sudarshan/resume_security_pipeline/uploads/Sudarshan_Resume copy.pdf"

# === Step 1: Extract Text (with OCR fallback for scanned PDFs) ===
def extract_text_from_pdf(pdf_path):
    """Extracts text from PDF, uses OCR if needed."""
    try:
        text = ""
        ocr_used = False  # Flag to track if OCR was used

        doc = fitz.open(pdf_path)
        for page in doc:
            page_text = page.get_text("text")
            if page_text.strip():
                text += page_text + "\n"

        # If no text is extracted, use OCR
        if not text.strip():
            print("⚠️ No text detected, using OCR...")
            text = extract_text_with_ocr(pdf_path)
            ocr_used = True  # Mark OCR as used

        return text.strip(), ocr_used
    except Exception as e:
        return f"⚠️ Error extracting text: {e}", False

def extract_text_with_ocr(pdf_path):
    """Uses OCR to extract text from scanned PDFs."""
    try:
        images = convert_from_path(pdf_path)
        full_text = ""
        for img in images:
            text = pytesseract.image_to_string(img)
            full_text += text + "\n"
        return full_text.strip()
    except Exception as e:
        return f"⚠️ OCR Error: {e}"

# === Step 2: Scan for Malware with VirusTotal ===
def scan_pdf_for_malware(pdf_path):
    """Scans the PDF file for malware using VirusTotal API."""
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
    """Analyzes text for PII, bias, and toxicity using NLP models."""
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

# === Step 4: Analyze PDF Metadata ===
def analyze_pdf_metadata(pdf_path):
    """Checks PDF for hidden metadata like author, timestamps."""
    doc = fitz.open(pdf_path)
    metadata = doc.metadata

    print("\n🔍 PDF Metadata Analysis:")
    if metadata:
        for key, value in metadata.items():
            print(f"📄 {key}: {value}")

        if "author" in metadata and metadata["author"]:
            print("⚠️ Warning: Author metadata detected (consider removing).")
        if "producer" in metadata and "Microsoft" in metadata["producer"]:
            print("⚠️ Warning: PDF may contain tracked edits from Microsoft Office.")
    else:
        print("✅ No metadata found.")

# === Step 5: Detect Embedded JavaScript ===
def detect_embedded_javascript(pdf_path):
    """Checks if PDF contains embedded JavaScript (potential malware)."""
    doc = fitz.open(pdf_path)
    print("\n🔍 JavaScript Security Scan:")
    for page_num in range(len(doc)):
        js_code = doc[page_num].get_text("text")
        if "JavaScript" in js_code or "/JS" in js_code:
            print(f"⚠️ Warning: JavaScript found on page {page_num + 1}")
            return
    print("✅ No JavaScript found in the PDF.")

# === Step 6: Extract & Analyze Links ===
def extract_urls_from_pdf(pdf_path):
    """Extracts links from PDF and detects suspicious ones."""
    doc = fitz.open(pdf_path)
    urls = []

    for page in doc:
        links = page.get_links()
        for link in links:
            if "uri" in link:
                urls.append(link["uri"])

    print("\n🔍 Link Analysis:")
    if urls:
        for url in urls:
            if re.search(r"(darkweb|.onion|bit.ly|tinyurl|phishing)", url):
                print(f"⚠️ Suspicious URL detected: {url}")
            else:
                print(f"🔗 Safe URL found: {url}")
    else:
        print("✅ No URLs found in the PDF.")

# === Step 7: Detect Suspicious Keywords ===
def scan_suspicious_keywords(text):
    """Detects fraudulent job offers, scam wording."""
    suspicious_keywords = [
        "urgent action", "claim your prize", "confidential", 
        "click here", "limited time offer", "instant hiring"
    ]
    
    print("\n🔍 Suspicious Keyword Analysis:")
    found_keywords = [kw for kw in suspicious_keywords if kw in text.lower()]

    if found_keywords:
        print(f"⚠️ Warning: Suspicious keywords found: {found_keywords}")
    else:
        print("✅ No suspicious keywords detected.")

# === Step 8: Detect Hidden Objects ===
def detect_hidden_objects(pdf_path):
    """Checks for embedded files, annotations (potential hidden malware)."""
    doc = fitz.open(pdf_path)
    print("\n🔍 Hidden Objects Detection:")

    if doc.has_annots():
        print("⚠️ Warning: Embedded annotations detected (potential hidden scripts).")
    
    if doc.embfile_count() > 0:  # Correct way to check for embedded files
        print(f"⚠️ Warning: PDF contains {doc.embfile_count()} embedded file(s) (potential malware).")
    else:
        print("✅ No hidden objects found.")



# === Step 9: Run All Security Checks ===
def run_security_checks(pdf_path):
    """Runs all security scans on the PDF."""
    print(f"\n🔍 Running security checks on: {pdf_path}\n")

    analyze_pdf_metadata(pdf_path)
    detect_embedded_javascript(pdf_path)
    extract_urls_from_pdf(pdf_path)
    detect_hidden_objects(pdf_path)

    resume_text, ocr_used = extract_text_from_pdf(pdf_path)
    if ocr_used:
        print("\n🟠 OCR was used to extract text from this document.")

    scan_suspicious_keywords(resume_text)

    malware_scan_result = scan_pdf_for_malware(pdf_path)
    print("\n✅ Malware Scan Result:", malware_scan_result)

    analysis_results = analyze_text(resume_text)
    print("\n🔍 PII Detected:", analysis_results["pii"])
    print("\n🧐 Bias Analysis:", analysis_results["bias"])
    print("\n☢️ Toxicity Analysis:", analysis_results["toxicity"])

# === Run the Script ===
run_security_checks(pdf_path)
