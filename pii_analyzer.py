import re
import spacy

try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    import spacy.cli
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")

def mask_value(pii_type, value):
    """Masks data for the UI so we don't display stolen data openly."""
    try:
        if pii_type == "Email Address":
            name, domain = value.split('@')
            return f"{name[:2]}***@{domain}"
        elif pii_type == "Indian Mobile":
            return f"{value[:3]}*****{value[-2:]}"
        elif pii_type == "Aadhaar Number":
            return f"**** **** {value[-4:]}"
        elif pii_type == "PAN Card":
            return f"{value[:2]}****{value[-1]}"
        else:
            return f"{value[:3]}***"
    except:
        return "********"

def extract_and_scan(text):
    """Extracts sensitive info to be used for hunting later."""
    findings =[]
    
    # Strictly defined Regex patterns
    patterns = {
        "Aadhaar Number": r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "PAN Card": r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b",
        "Indian Mobile": r"\b(\+91[\-\s]?)?[6-9]\d{9}\b",
        "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "API Key": r"(api_key|apikey|secret)[\s=:'\"]+([A-Za-z0-9\-_]{16,})"
    }

    # 1. Regex Extraction
    for pii_type, regex in patterns.items():
        for match in re.finditer(regex, text, re.IGNORECASE):
            val = match.group(2) if len(match.groups()) > 1 else match.group(0)
            val = val.strip()
            
            # Determine if this is a "Huntable" item. (We can't easily Google an Aadhaar, but we can Google an Email).
            is_huntable = True if pii_type in["Email Address", "Indian Mobile"] else False
            
            findings.append({
                "Type": pii_type,
                "Raw Value": val,
                "Masked Value": mask_value(pii_type, val),
                "Huntable": is_huntable
            })

    # Remove duplicates
    unique_findings =[]
    seen = set()
    for f in findings:
        if f['Raw Value'] not in seen:
            seen.add(f['Raw Value'])
            unique_findings.append(f)

    return unique_findings