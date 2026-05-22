from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import socket
import whois
import requests
from datetime import datetime
import os


VT_API_KEY = os.getenv("VT_API_KEY")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class URLRequest(BaseModel):
    url: str


@app.get("/")
def home():
    return {"message": "Backend is working!"}


def check_virustotal(url):
    if not VT_API_KEY:
        return None

    try:
        headers = {"x-apikey": VT_API_KEY}

        response = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        )

        if response.status_code != 200:
            return None

        result = response.json()
        analysis_id = result["data"]["id"]

        report = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        )

        if report.status_code != 200:
            return None

        stats = report.json()["data"]["attributes"]["stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return malicious + suspicious

    except:
        return None


@app.post("/analyze-url")
def analyze(data: URLRequest):
    url = data.url.lower().strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "")

    score = 0
    reasons = []

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

    try:
        socket.gethostbyname(domain)
    except:
        score += 25
        reasons.append("Domain does not resolve")

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

    vt_hits = check_virustotal(url)

    if vt_hits is not None:
        if vt_hits > 0:
            score += min(vt_hits * 10, 40)
            reasons.append(f"Flagged by {vt_hits} security vendors")
        else:
            reasons.append("No VirusTotal detections")
    else:
        reasons.append("VirusTotal check unavailable")

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