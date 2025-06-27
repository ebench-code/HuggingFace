import gradio as gr
import json
import os
import re
import spacy

# Lazy load spaCy
nlp = None
def get_nlp():
    global nlp
    if nlp is None:
        try:
            nlp = spacy.load("en_core_web_sm")
        except OSError:
            import subprocess
            subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"], check=True)
            nlp = spacy.load("en_core_web_sm")
    return nlp

REDACTION_MAP = {
    "PERSON": "REDACTED_PERSON",
    "GPE": "REDACTED_LOCATION",
    "LOC": "REDACTED_LOCATION",
}

def redact_with_regex(text):
    text = re.sub(r'\b\S+@\S+\b', 'REDACTED_EMAIL', text)  # Email
    text = re.sub(r'\b(?:\+?1\s*[-.]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b', 'REDACTED_PHONE', text)  # Phone
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', 'REDACTED_SSN', text)  # SSN
    text = re.sub(r'\b\d{1,5}\s+\w+(?:\s\w+)*,\s*\w+(?:\s\w+)*,\s*[A-Z]{2,}?\s*\d{5}\b', 'REDACTED_ADDRESS', text)  # Full address
    text = re.sub(r'\b\d{1,5}\s+\w+(?:\s\w+)*\b', 'REDACTED_ADDRESS', text)  # Partial address fallback
    return text

def redact_sentence(text):
    text = redact_with_regex(text)
    doc = get_nlp()(text)
    redacted = text
    for ent in reversed(doc.ents):
        replacement = REDACTION_MAP.get(ent.label_)
        if replacement:
            redacted = redacted[:ent.start_char] + replacement + redacted[ent.end_char:]
    return redacted

def read_uploaded_file(file_obj):
    try:
        if hasattr(file_obj, "read"):
            content = file_obj.read().decode("utf-8")
        elif isinstance(file_obj, str) and os.path.isfile(file_obj):
            with open(file_obj, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            return "", "Could not read file."
        return content, None
    except Exception as e:
        return "", f"Read error: {e}"

def process_with_spacy(file_obj):
    content, err = read_uploaded_file(file_obj)
    if err:
        return [{"error": err}], ""

    lines = content.splitlines()
    results = []

    for line in lines:
        line = line.strip().rstrip(",")
        if not line or line in ["{}", "{", "}}", "{}}"]:
            continue
        if not line.startswith("{"):
            line = "{" + line
        if not line.endswith("}"):
            line = line + "}"

        try:
            obj = json.loads(line)
            if "sentence" in obj and isinstance(obj["sentence"], str):
                obj["sentence"] = redact_sentence(obj["sentence"])
            results.append(obj)
        except json.JSONDecodeError:
            continue

    cleaned_json = json.dumps(results, indent=2)
    with open("cleaned_output.json", "w", encoding="utf-8") as f:
        f.write(cleaned_json)

    return results, "cleaned_output.json"

with gr.Blocks() as demo:
    gr.Markdown("### Redact Sensitive Info in JSON with spaCy + Regex")
    file_input = gr.File(label="Upload your .json or .txt file", file_types=[".json", ".txt"])
    output = gr.JSON(label="Redacted Output")
    download_btn = gr.File(label="Download Cleaned JSON")

    def wrapped_process(file):
        result, out_path = process_with_spacy(file)
        return result, out_path

    file_input.change(fn=wrapped_process, inputs=file_input, outputs=[output, download_btn])

demo.launch()
