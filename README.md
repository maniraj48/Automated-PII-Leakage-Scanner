# 🛡️ Automated-PII-Leakage-Scanner

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-1.25+-FF4B4B.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**Sentinel OSINT** is a high-performance Digital Footprint analyzer designed to hunt for leaked Personally Identifiable Information (PII) across the public web. It extracts sensitive data from unstructured text and proactively searches platforms like **GitHub, Reddit, Facebook, Instagram, and LinkedIn** to identify real-time exposures.

---

## 🚀 The Problem
Accidental data leaks are a global crisis. Developers often hardcode API keys, and users unknowingly post Aadhaar numbers or emails on public forums. Under the **Indian DPDP Act**, these leaks result in massive security risks and legal penalties. Existing tools are often "passive" or "local only."

## ✨ Our Solution: The Sentinel Approach
Sentinel OSINT acts as an **Active Hunter**. It doesn't just scan files; it uses the user's own data to crawl the global internet index, finding exactly where their identity is compromised.

### **Key Features**
- 🧠 **AI-Powered Extraction:** Uses a hybrid of **Regex** (for structured data like Aadhaar/PAN) and **spaCy NLP** (for unstructured data like names).
- 🌐 **Multi-Platform OSINT Hunt:** 
    - **GitHub:** Real-time search in public repositories via GitHub API.
    - **Social Media:** Uses advanced **Google Dorking** to bypass API restrictions on Facebook, Instagram, and LinkedIn.
    - **Reddit:** Crawls public forums for PII mentions.
- 📊 **Risk Intelligence Dashboard:** Provides an interactive breakdown of exposure types, platform distribution, and a weighted **Risk Score (0-100)**.
- 🛡️ **Privacy-First Design:** Features an **Auto-Redaction** toggle to mask sensitive data on the dashboard.
- 📄 **Compliance Reporting:** Generates downloadable security audit reports for remediation.

---

## 🛠️ Tech Stack
- **Frontend:** Streamlit (Modern SaaS UI)
- **Analytics:** Plotly Express (Interactive Charts)
- **PII Engine:** Regex (Custom Patterns) + spaCy (Named Entity Recognition)
- **APIs & Scraping:** 
    - `PyGithub` (GitHub API)
    - `Google Custom Search API` (OSINT Dorking Engine)
    - `BeautifulSoup4` & `Requests` (Web Scraping)

---

## 📐 System Architecture
1. **Input Layer:** User pastes unstructured text (logs, code snippets, or personal bios).
2. **Extraction Layer:** The AI Brain identifies huntable identifiers (Emails, Phone Numbers) and sensitive IDs (Aadhaar, PAN).
3. **OSINT Layer:** The system fans out queries to GitHub and Google's Global Index.
4. **Intelligence Layer:** Data is aggregated, risk-scored, and visualized on the dashboard.

---
