import fitz 
import pdfid
import clamd
import pytesseract
from pdf2image import convert_from_path
from transformers import pipeline
import sqlite3
from flask import Flask, request, jsonify

# Load AI models (Runs locally for free)
# Load AI models (Runs locally for free)
pii_detector = pipeline("ner", model="obi/deid_roberta_i2b2")
bias_detector = pipeline("text-classification", model="unitary/unbiased-toxic-roberta")  # ✅ Replaced
toxicity_detector = pipeline("text-classification", model="unitary/toxic-bert")
fake_text_detector = pipeline("text-classification", model="roberta-large-openai-detector")


### Step 1: Extract Text from PDF ###
def extract_text_from_pdf(pdf_path):
    try:
        text = ""
        doc = fitz.open(pdf_path)
        for page in doc:
            text += page.get_text("text") + "\n"
        return text.strip() if text else None
    except Exception as e:
        print(f"Error extracting text: {e}")
        return None

### Step 2: Scan PDF for Malware ###
def scan_pdf_for_malware(pdf_path):
    try:
        # Check for suspicious scripts
        result = pdfid.PDFiD(pdf_path)
        if any(keyword in result for keyword in ["/JS", "/Launch", "/OpenAction"]):
            return "⚠️ Warning: Suspicious elements detected in PDF!"
        
        # Scan for viruses using ClamAV
        clamd_client = clamd.ClamdUnixSocket()
        scan_result = clamd_client.scan(pdf_path)
        if "FOUND" in str(scan_result):
            return "⚠️ Virus detected in PDF!"
        
        return "✅ No malware detected."
    except Exception as e:
        return f"⚠️ Error scanning for malware: {e}"

### Step 3: Convert Scanned PDFs to Text (OCR) ###
def extract_text_from_scanned_pdf(pdf_path):
    images = convert_from_path(pdf_path)
    full_text = ""
    for img in images:
        text = pytesseract.image_to_string(img)
        full_text += text + "\n"
    return full_text.strip()

### Step 4: Detect PII, Bias, Toxicity, and Fake Content ###
def analyze_text(text):
    results = {
        "pii": pii_detector(text),
        "bias": bias_detector(text),
        "toxicity": toxicity_detector(text),
        "fake_text": fake_text_detector(text)
    }
    return results

### Step 5: Store Processed Data Securely ###
def store_in_database(file_name, text, analysis_results):
    conn = sqlite3.connect("resumes.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS resumes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_name TEXT,
            text TEXT,
            pii TEXT,
            bias TEXT,
            toxicity TEXT,
            fake_text TEXT
        )
    """)
    cursor.execute("INSERT INTO resumes (file_name, text, pii, bias, toxicity, fake_text) VALUES (?, ?, ?, ?, ?, ?)",
                   (file_name, text, str(analysis_results["pii"]), str(analysis_results["bias"]),
                    str(analysis_results["toxicity"]), str(analysis_results["fake_text"])))
    conn.commit()
    conn.close()

### Step 6: Full Resume & Job Description Processing ###
def process_resume(pdf_path):
    print(f"🔍 Processing {pdf_path}...")
    
    # Malware scanning
    malware_result = scan_pdf_for_malware(pdf_path)
    
    # Extract text
    resume_text = extract_text_from_pdf(pdf_path)
    if not resume_text:
        print("⚠️ PDF contains images only. Using OCR...")
        resume_text = extract_text_from_scanned_pdf(pdf_path)

    if not resume_text:
        return {"error": "Unable to extract text from PDF."}

    # Analyze text
    analysis_results = analyze_text(resume_text)

    # Store results
    store_in_database(pdf_path, resume_text, analysis_results)

    return {
        "file": pdf_path,
        "malware_scan": malware_result,
        "resume_text": resume_text[:500] + "..." if len(resume_text) > 500 else resume_text,
        "pii_detection": analysis_results["pii"],
        "bias_analysis": analysis_results["bias"],
        "toxicity_analysis": analysis_results["toxicity"],
        "fake_text_detection": analysis_results["fake_text"]
    }

### Step 7: Flask API for Real-Time Analysis ###
app = Flask(__name__)

@app.route("/scan", methods=["POST"])
def scan_resume():
    file = request.files.get("file")
    if not file:
        return jsonify({"error": "No file uploaded."}), 400

    file_path = f"./uploads/{file.filename}"
    file.save(file_path)

    result = process_resume(file_path)
    return jsonify(result)

if __name__ == "__main__":
    app.run(port=5000)