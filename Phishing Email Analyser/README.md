# Phishing Email Analyzer (Secure Mode)

**Version**: 1.0.0  
**Last Updated**: June 2025  
**Author**: [Arvindhsiv]

---

## 📖 Overview

**Phishing Email Analyzer (Secure Mode)** is an enterprise-grade, Python/Tkinter-based desktop application designed to help security engineers rapidly triage `.eml` files. Leveraging VirusTotal’s API and DNS-based DMARC lookups, this tool provides:

1. **Email Header Extraction**  
   - Source Address, Return-Path, Message-ID, Reply-To  
   - Exhaustive “Received” headers (mail hops)  

2. **Attachment Analysis**  
   - In-memory SHA-256 hash computation (no disk writes)  
   - VirusTotal verdict (malicious vs. clean)  

3. **URL Extraction & Reputation**  
   - Regex + `urllib.parse`‐based URL sanitization  
   - VirusTotal URL verdicts (malicious vs. clean)  

4. **DMARC Policy Lookup**  
   - DNS TXT query for `_dmarc.<domain>`  
   - Displays raw DMARC policy or “Not found”  

5. **Classification Heuristic**  
   - **Phish**: Any malicious attachment or URL  
   - **Spam**: Attachments or >2 URLs, none malicious  
   - **Legitimate**: No suspicious indicators  

6. **Security Hardening**  
   - **No hard-coded API keys**: `VT_API_KEY` is read from environment  
   - **Least-Privilege**: refuses to run under root/Administrator  
   - **Asynchronous network calls**: prevents UI hangs or API-driven DoS  
   - **File-size & extension checks**: blocks oversized or non-EML inputs  
   - **Input Sanitization**: headers & URLs are scrubbed of control chars  
   - **Structured Logging**: all events write to `~/.phish_analyzer/logs/phish_analyzer.log`  

---

