from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
import socket
import whois
import requests
from datetime import datetime

# CONFIG
VT_API_KEY = "ca36d89438639f95586b9e775f8be0df49426f01ba2719559d0012453aedc32c"

app = FastAPI()

# INPUT MODEL

class URLRequest(BaseModel):
    url: str

# HOME ROUTE
@app.get("/")
def home():
    return {"message": "Backend is working!"}

# VIRUSTOTAL CHECK
def check_virustotal(url):
    try:
        headers = {
            "x-apikey": VT_API_KEY
        }

        # Submit URL
        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            return None

        result = response.json()
        analysis_id = result["data"]["id"]

        # Get report
        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        stats = report.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return malicious + suspicious

    except:
        return None

# MAIN ANALYZER
@app.post("/analyze-url")
def analyze(data: URLRequest):

    url = data.url.lower().strip()

    # Add http if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    score = 0
    reasons = []

    # BASIC URL CHECKS
    suspicious_words = [
        "login",
        "verify",
        "bank",
        "secure",
        "update",
        "paypal"
    ]

    for word in suspicious_words:
        if word in url:
            score += 12
            reasons.append(f"Suspicious keyword: {word}")

    if "@" in url:
        score += 30
        reasons.append("Contains @ symbol")

    if "-" in domain:
        score += 12
        reasons.append("Hyphenated domain")

    if domain.count(".") > 2:
        score += 15
        reasons.append("Too many subdomains")

    if len(url) > 80:
        score += 10
        reasons.append("Very long URL")

    if not url.startswith("https://"):
        score += 10
        reasons.append("Not using HTTPS")

    # DNS CHECK
    try:
        socket.gethostbyname(domain)
    except:
        score += 25
        reasons.append("Domain does not resolve")

    # WHOIS DOMAIN AGE CHECK
    try:
        info = whois.whois(domain)
        created = info.creation_date

        if isinstance(created, list):
            created = created[0]

        if created:
            age_days = (datetime.now() - created).days

            if age_days < 30:
                score += 35
                reasons.append("Very new domain (<30 days)")

            elif age_days < 180:
                score += 20
                reasons.append("Recently created domain")

    except:
        reasons.append("Domain age unavailable")

    # TRUSTED DOMAINS
    trusted = [
        "google.com",
        "microsoft.com",
        "apple.com",
        "amazon.in",
        "openai.com"
    ]

    if domain in trusted:
        score -= 25
        reasons.append("Recognized trusted domain")

    # VIRUSTOTAL CHECK
    vt_hits = check_virustotal(url)

    if vt_hits is not None:
        if vt_hits > 0:
            score += min(vt_hits * 10, 40)
            reasons.append(f"Flagged by {vt_hits} security vendors")
        else:
            reasons.append("No VirusTotal detections")
    else:
        reasons.append("VirusTotal check unavailable")

    # FINAL SCORE
    score = max(0, min(score, 100))

    if score >= 70:
        status = "phishing"
    elif score >= 35:
        status = "suspicious"
    else:
        status = "safe"

    return {
        "url": data.url,
        "domain": domain,
        "status": status,
        "risk_score": score,
        "reasons": reasons
    }