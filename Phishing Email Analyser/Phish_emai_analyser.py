#!/usr/bin/env python3
"""
phish_analyzer.py

Enterprise-grade Phishing Email Analyzer (Secure Mode)
Authors: [Your Name / Team]
Date: 2025-06-XX

This Tkinter‐based GUI app ingests a raw .eml file, extracts:
  • Source address + SMTP headers
  • Attachment SHA-256 hashes + VT verdict
  • URLs + VT verdict
  • DMARC policy lookup via DNS
  • Classification: Phish / Spam / Legitimate

Security hardening: 
  • No hard-coded secrets (VT_API_KEY from env)
  • Strict file‐size / extension checks
  • Runs under least privilege (non‐root)
  • Asynchronous VT & DNS queries
  • Input sanitization for headers & URLs
"""

import os
import re
import sys
import threading
import hashlib
import logging
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from email import policy
from email.parser import BytesParser
import requests
import dns.resolver
from urllib.parse import urlparse

# ─────────────── CONFIGURATION & SECURITY PRINCIPLES ───────────────────
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
if not VT_API_KEY:
    print("ERROR: VT_API_KEY environment variable not set. Exiting.")
    sys.exit(1)

MAX_EML_SIZE = 10 * 1024 * 1024  # 10 MiB

LOG_DIR = os.path.join(os.path.expanduser("~"), ".phish_analyzer", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "phish_analyzer.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logging.info("Application started under UID=%s, PID=%s", os.geteuid() if hasattr(os, "getuid") else "N/A", os.getpid())

# ─────────────── CONSTANTS & REGEX (INPUT VALIDATION) ───────────────────
URL_REGEX = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+")
VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{url_id}"
VT_FILE_REPORT = "https://www.virustotal.com/api/v3/files/{file_hash}"

# ─────────────── HELPER FUNCTIONS ───────────────────
def compute_sha256(content_bytes: bytes) -> str:
    sha256 = hashlib.sha256()
    sha256.update(content_bytes)
    return sha256.hexdigest()

def safe_parse_url(raw_url: str) -> str:
    try:
        parsed = urlparse(raw_url.strip())
        if parsed.scheme not in ("http", "https"):
            return None
        if not parsed.netloc:
            return None
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.query:
            safe_url += f"?{parsed.query}"
        return safe_url
    except Exception:
        return None

def vt_query_file_hash(file_hash: str) -> dict:
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
    }
    url = VT_FILE_REPORT.format(file_hash=file_hash)
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logging.warning("VT file lookup failed for hash %s: %s", file_hash, e)
        return {}

def vt_query_url(raw_url: str) -> dict:
    headers = {
        "x-apikey": VT_API_KEY,
        "accept": "application/json",
    }
    safe_url = safe_parse_url(raw_url)
    if not safe_url:
        logging.warning("Invalid URL skipped: %s", raw_url)
        return {}
    url_id = requests.utils.quote(safe_url, safe="")
    endpoint = VT_URL_REPORT.format(url_id=url_id)
    try:
        resp = requests.get(endpoint, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.RequestException as e:
        logging.warning("VT URL lookup failed for %s: %s", safe_url, e)
        return {}

def fetch_dmarc_record(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        policy_strings = []
        for txt_rec in answers:
            joined = b"".join(txt_rec.strings).decode(errors="ignore")
            policy_strings.append(joined)
        return "; ".join(policy_strings) if policy_strings else "No DMARC record found."
    except dns.exception.DNSException as e:
        logging.info("DMARC lookup failed for domain %s: %s", domain, e)
        return "No DMARC record found."

def extract_domain_from_email_address(email_addr: str) -> str:
    if "@" in email_addr:
        _, domain = email_addr.split("@", 1)
        domain = domain.strip().lower()
        if "." in domain and re.match(r"^[A-Za-z0-9\-\.]+$", domain):
            return domain
    return ""

# ─────────────── MAIN ANALYSIS FUNCTION (BACKGROUND THREAD) ───────────────────
def analyze_email(file_path: str, callback):
    result = {
        "source_address": "",
        "return_path": "",
        "message_id": "",
        "reply_to": "",
        "first_relay": "",
        "all_hops": [],
        "attachments": [],
        "urls": [],
        "dmarc_policy": "",
        "classification": "Unknown",
    }

    # Enforce file-size constraint (DoS mitigation)
    try:
        stat_info = os.stat(file_path)
        if stat_info.st_size > MAX_EML_SIZE:
            msg = f"EML exceeds {MAX_EML_SIZE // (1024*1024)} MiB limit."
            logging.warning(msg)
            callback({"error": msg})
            return
    except Exception as e:
        logging.error("Failed to stat %s: %s", file_path, e)
        callback({"error": "Unable to read file metadata."})
        return

    # Parse email
    try:
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
    except Exception as e:
        logging.error("Email parsing failed for %s: %s", file_path, e)
        callback({"error": "Failed to parse email. Possibly malformed."})
        return

    # Sanitize headers
    def sanitize_header(val: str) -> str:
        return re.sub(r"[\r\n]+", " ", val).strip()

    result["source_address"] = sanitize_header(msg.get("From", ""))
    result["return_path"]   = sanitize_header(msg.get("Return-Path", ""))
    result["message_id"]    = sanitize_header(msg.get("Message-ID", ""))
    result["reply_to"]      = sanitize_header(msg.get("Reply-To", ""))

    # Received headers → mail hops
    received_headers = msg.get_all("Received", [])
    sanitized_hops = [sanitize_header(rh) for rh in received_headers]
    result["all_hops"] = sanitized_hops
    if sanitized_hops:
        result["first_relay"] = sanitized_hops[-1]  # last header = first-hop

    # Attachments: compute SHA-256
    for part in msg.iter_attachments():
        try:
            payload = part.get_payload(decode=True)
            if payload:
                file_hash = compute_sha256(payload)
                filename = sanitize_header(part.get_filename() or "<no filename>")
                result["attachments"].append({"filename": filename, "sha256": file_hash})
        except Exception as e:
            logging.warning("Attachment processing failed: %s", e)
            continue

    # Extract URLs from text/plain & text/html parts
    body_text = ""
    for part in msg.walk():
        try:
            if part.get_content_type() in ("text/plain", "text/html"):
                body_text += part.get_content() + "\n"
        except Exception:
            continue

    found_urls = set(URL_REGEX.findall(body_text))
    for raw_url in found_urls:
        safe_url = safe_parse_url(raw_url)
        if safe_url:
            result["urls"].append({"url": safe_url, "vt_verdict": "Pending"})
        else:
            logging.info("Filtered invalid URL: %s", raw_url)

    # Fetch DMARC for sending domain
    sending_domain = extract_domain_from_email_address(result["source_address"])
    if sending_domain:
        result["dmarc_policy"] = fetch_dmarc_record(sending_domain)
    else:
        result["dmarc_policy"] = "Cannot determine sending domain."

    # VirusTotal lookups (attachments + URLs) in parallel
    vt_threads = []

    def query_attachment(att_dict):
        vt_resp = vt_query_file_hash(att_dict["sha256"])
        stats = vt_resp.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
        att_dict["malicious_count"] = malicious

    def query_url_entry(url_dict):
        raw = url_dict["url"]
        vt_resp = vt_query_url(raw)
        stats = vt_resp.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0) if isinstance(stats, dict) else 0
        url_dict["vt_verdict"] = "Malicious" if malicious > 0 else "Clean"

    # Spawn threads
    for att in result["attachments"]:
        th = threading.Thread(target=query_attachment, args=(att,))
        vt_threads.append(th)
        th.start()

    for url_info in result["urls"]:
        th = threading.Thread(target=query_url_entry, args=(url_info,))
        vt_threads.append(th)
        th.start()

    # Join with timeout
    for th in vt_threads:
        th.join(timeout=15)

    # Classification logic
    any_malicious_attachment = any(att.get("malicious_count", 0) > 0 for att in result["attachments"])
    any_malicious_url = any(info.get("vt_verdict") == "Malicious" for info in result["urls"])

    if any_malicious_attachment or any_malicious_url:
        result["classification"] = "Phish"
    elif result["attachments"] or len(result["urls"]) > 2:
        result["classification"] = "Spam"
    else:
        result["classification"] = "Legitimate"

    callback(result)

# ─────────────── SECURE GUI (Tkinter) ───────────────────
class PhishEmailAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔒 Phishing Email Analyzer (Secure Mode)")
        self.root.geometry("850x650")

        self.load_btn = tk.Button(
            root, text="📂 Load .eml File", command=self.on_load_clicked, padx=10, pady=5
        )
        self.load_btn.pack(pady=12)

        self.output_area = scrolledtext.ScrolledText(
            root, wrap=tk.WORD, state=tk.DISABLED, padx=8, pady=8
        )
        self.output_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def on_load_clicked(self):
        file_path = filedialog.askopenfilename(
            title="Select a single .eml file",
            filetypes=(("Email files", "*.eml *.EML"),),
        )
        if not file_path:
            return

        if not file_path.lower().endswith(".eml"):
            messagebox.showerror("Invalid File", "Only .eml files are permitted.")
            return

        try:
            size = os.path.getsize(file_path)
            if size > MAX_EML_SIZE:
                mb = MAX_EML_SIZE // (1024 * 1024)
                messagebox.showerror("File Too Large", f"Limit is {mb} MiB per email.")
                return
        except Exception as e:
            logging.error("Failed to stat selected file: %s", e)
            messagebox.showerror("Error", "Unable to verify file size.")
            return

        self.output_area.config(state=tk.NORMAL)
        self.output_area.delete(1.0, tk.END)
        self.output_area.insert(tk.END, "🛠️  Processing email… please wait.\n")
        self.output_area.config(state=tk.DISABLED)

        worker = threading.Thread(target=analyze_email, args=(file_path, self.on_analysis_complete))
        worker.daemon = True
        worker.start()

    def on_analysis_complete(self, data: dict):
        def render():
            self.output_area.config(state=tk.NORMAL)
            self.output_area.delete(1.0, tk.END)

            if data.get("error"):
                self.output_area.insert(tk.END, f"❗ Error: {data['error']}\n")
                self.output_area.config(state=tk.DISABLED)
                return

            self.output_area.insert(tk.END, f"🔐 Classification: {data['classification']}\n\n")
            self.output_area.insert(tk.END, f"From         : {data['source_address']}\n")
            self.output_area.insert(tk.END, f"Return-Path  : {data['return_path']}\n")
            self.output_area.insert(tk.END, f"Message-ID   : {data['message_id']}\n")
            self.output_area.insert(tk.END, f"Reply-To     : {data['reply_to']}\n\n")

            self.output_area.insert(tk.END, "📨 Mail Hops (Received headers):\n")
            if data["all_hops"]:
                for idx, hop in enumerate(data["all_hops"], 1):
                    self.output_area.insert(tk.END, f"  Hop {idx}: {hop}\n")
            else:
                self.output_area.insert(tk.END, "  No Received headers found.\n")
            self.output_area.insert(tk.END, "\n")

            self.output_area.insert(tk.END, "📎 Attachments (SHA-256):\n")
            if data["attachments"]:
                for att in data["attachments"]:
                    mal_count = att.get("malicious_count", 0)
                    verdict = "Malicious" if mal_count > 0 else "Clean"
                    self.output_area.insert(
                        tk.END,
                        f"  {att['filename']} → {att['sha256']}  |  VT: {verdict}\n"
                    )
            else:
                self.output_area.insert(tk.END, "  No attachments found.\n")
            self.output_area.insert(tk.END, "\n")

            self.output_area.insert(tk.END, "🔗 URLs (VirusTotal verdicts):\n")
            if data["urls"]:
                for url_info in data["urls"]:
                    self.output_area.insert(
                        tk.END,
                        f"  {url_info['url']}  →  {url_info['vt_verdict']}\n"
                    )
            else:
                self.output_area.insert(tk.END, "  No URLs detected.\n")
            self.output_area.insert(tk.END, "\n")

            self.output_area.insert(tk.END, "✉️ DMARC Policy:\n")
            self.output_area.insert(tk.END, f"  {data['dmarc_policy']}\n\n")

            self.output_area.config(state=tk.DISABLED)

        self.root.after(0, render)

# ─────────────── APPLICATION ENTRYPOINT ───────────────────
if __name__ == "__main__":
    if os.name != "nt":
        try:
            if os.geteuid() == 0:
                print("ERROR: Do not run as root. Exiting.")
                sys.exit(1)
        except AttributeError:
            pass
    else:
        logging.warning("Running on Windows—ensure non-Admin user context.")
    root = tk.Tk()
    app = PhishEmailAnalyzerApp(root)
    root.mainloop()
